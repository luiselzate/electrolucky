import asyncio
from decimal import Decimal
import threading
from typing import TYPE_CHECKING, List, Optional, Dict, Any
from urllib.parse import urlparse

from kivy.app import App
from kivy.clock import Clock
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.recycleview import RecycleView
from kivy.properties import StringProperty

from electrum.invoices import (PR_DEFAULT_EXPIRATION_WHEN_CREATING,
                               PR_PAID, PR_UNKNOWN, PR_EXPIRED, PR_INFLIGHT,
                               pr_expiration_values, Invoice)
from electrum import bitcoin, constants
from electrum import lnutil
from electrum.transaction import tx_from_any, PartialTxOutput
from electrum.util import (parse_URI, InvalidBitcoinURI, TxMinedInfo, maybe_extract_lightning_payment_identifier,
                           InvoiceError, format_time, parse_max_spend, BITCOIN_BIP21_URI_SCHEME)
from electrum.lnaddr import lndecode, LnInvoiceException
from electrum.lnurl import decode_lnurl, request_lnurl, callback_lnurl, LNURLError, LNURL6Data
from electrum.logging import Logger
from electrum.network import Network

from .dialogs.confirm_tx_dialog import ConfirmTxDialog

from electrum.gui.kivy import KIVY_GUI_PATH
from electrum.gui.kivy.i18n import _

if TYPE_CHECKING:
    from electrum.gui.kivy.main_window import ElectrumWindow
    from electrum.paymentrequest import PaymentRequest


class HistoryRecycleView(RecycleView):
    pass

class RequestRecycleView(RecycleView):
    pass

class PaymentRecycleView(RecycleView):
    pass

class CScreen(Factory.Screen):
    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')
    action_view = ObjectProperty(None)
    kvname = None
    app = App.get_running_app()  # type: ElectrumWindow

    def on_enter(self):
        # FIXME: use a proper event don't use animation time of screen
        Clock.schedule_once(lambda dt: self.dispatch('on_activate'), .25)
        pass

    def update(self):
        pass

    def on_activate(self):
        setattr(self.app, self.kvname + '_screen', self)
        self.update()

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        pass


# note: this list needs to be kept in sync with another in qt
TX_ICONS = [
    "unconfirmed",
    "close",
    "unconfirmed",
    "close",
    "clock1",
    "clock2",
    "clock3",
    "clock4",
    "clock5",
    "confirmed",
]


Builder.load_file(KIVY_GUI_PATH + '/uix/ui_screens/history.kv')
Builder.load_file(KIVY_GUI_PATH + '/uix/ui_screens/send.kv')
Builder.load_file(KIVY_GUI_PATH + '/uix/ui_screens/receive.kv')


class HistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'history'
    cards = {}

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(HistoryScreen, self).__init__(**kwargs)

    def show_item(self, obj):
        key = obj.key
        tx_item = self.history.get(key)
        if tx_item.get('lightning') and tx_item['type'] == 'payment':
            self.app.lightning_tx_dialog(tx_item)
            return
        if tx_item.get('lightning'):
            tx = self.app.wallet.adb.get_transaction(key)
        else:
            tx = self.app.wallet.db.get_transaction(key)
        if not tx:
            return
        self.app.tx_dialog(tx)

    def get_card(self, tx_item): #tx_hash, tx_mined_status, value, balance):
        is_lightning = tx_item.get('lightning', False)
        timestamp = tx_item['timestamp']
        key = tx_item.get('txid') or tx_item['payment_hash']
        if is_lightning:
            status_str = 'unconfirmed' if timestamp is None else format_time(int(timestamp))
            icon = f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/lightning'
            message = tx_item['label']
            fee_msat = tx_item['fee_msat']
            fee = int(fee_msat/1000) if fee_msat else None
            fee_text = '' if fee is None else 'fee: %d sat'%fee
        else:
            tx_hash = tx_item['txid']
            tx_mined_info = TxMinedInfo(height=tx_item['height'],
                                        conf=tx_item['confirmations'],
                                        timestamp=tx_item['timestamp'])
            status, status_str = self.app.wallet.get_tx_status(tx_hash, tx_mined_info)
            icon = f'atlas://{KIVY_GUI_PATH}/theming/atlas/light/' + TX_ICONS[status]
            message = tx_item['label'] or tx_hash
            fee = tx_item['fee_sat']
            fee_text = '' if fee is None else 'fee: %d sat'%fee
        ri = {}
        ri['screen'] = self
        ri['key'] = key
        ri['icon'] = icon
        ri['date'] = status_str
        ri['message'] = message
        ri['fee_text'] = fee_text
        value = tx_item['value'].value
        if value is not None:
            ri['is_mine'] = value <= 0
            ri['amount'] = self.app.format_amount(value, is_diff=True)
            ri['base_unit'] = self.app.base_unit
            if 'fiat_value' in tx_item:
                ri['quote_text'] = str(tx_item['fiat_value'])
                ri['fx_ccy'] = tx_item['fiat_value'].ccy
        return ri

    def update(self, see_all=False):
        wallet = self.app.wallet
        if wallet is None:
            return
        self.history = wallet.get_full_history(self.app.fx)
        history = reversed(self.history.values())
        history_card = self.ids.history_container
        history_card.data = [self.get_card(item) for item in history]


class SendScreen(CScreen, Logger):

    kvname = 'send'
    payment_request = None  # type: Optional[PaymentRequest]
    parsed_URI = None
    lnurl_data = None  # type: Optional[LNURL6Data]

    def __init__(self, **kwargs):
        CScreen.__init__(self, **kwargs)
        Logger.__init__(self)
        self.is_max = False
        # note: most the fields get declared in send.kv, this way they are kivy Properties

    def set_URI(self, text: str):
        """Takes
        Lightning identifiers:
        * lightning-URI (containing bolt11 or lnurl)
        * bolt11 invoice
        * lnurl
        Bitcoin identifiers:
        * bitcoin-URI
        * bitcoin address
        and sets the sending screen.

        TODO maybe rename method...
        """
        if not self.app.wallet:
            return
        text = text.strip()
        if not text:
            return
        if invoice_or_lnurl := maybe_extract_lightning_payment_identifier(text):
            if invoice_or_lnurl.startswith('lnurl'):
                self.set_lnurl6(invoice_or_lnurl)
            else:
                self.set_bolt11(invoice_or_lnurl)
        elif text.lower().startswith(BITCOIN_BIP21_URI_SCHEME + ':') or bitcoin.is_address(text):
            self.set_bip21(text)
        else:
            self.app.show_error(f"Failed to parse text: {text[:10]}...")
            return

    def set_bip21(self, text: str):
        try:
            uri = parse_URI(text, self.app.on_pr, loop=self.app.asyncio_loop)
        except InvalidBitcoinURI as e:
            self.app.show_info(_("Error parsing URI") + f":\n{e}")
            return
        self.parsed_URI = uri
        amount = uri.get('amount')
        self.address = uri.get('address', '')
        self.message = uri.get('message', '')
        self.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.is_max = False
        self.payment_request = None
        self.is_lightning = False

    def set_bolt11(self, invoice: str):
        try:
            invoice = str(invoice).lower()
            lnaddr = lndecode(invoice)
        except LnInvoiceException as e:
            self.app.show_info(_("Invoice is not a valid Lightning invoice: ") + repr(e)) # repr because str(Exception()) == ''
            return
        except lnutil.IncompatibleOrInsaneFeatures as e:
            self.app.show_info(_("Invoice requires unknown or incompatible Lightning feature") + f":\n{e!r}")
            return
        self.address = invoice
        self.message = lnaddr.get_description()
        self.amount = self.app.format_amount_and_units(lnaddr.amount * bitcoin.COIN) if lnaddr.amount else ''
        self.payment_request = None
        self.is_lightning = True

    def set_lnurl6(self, lnurl: str):
        url = decode_lnurl(lnurl)
        domain = urlparse(url).netloc
        try:
            # FIXME network request blocking GUI thread:
            lnurl_data = Network.run_from_another_thread(request_lnurl(url))
        except LNURLError as e:
            self.app.show_error(f"LNURL request encountered error: {e}")
            self.do_clear()
            return
        self.lnurl_data = lnurl_data
        self.address = "invoice from lnurl"
        self.message = f"lnurl: {domain}: {lnurl_data.metadata_plaintext}"
        self.amount = self.app.format_amount_and_units(lnurl_data.min_sendable_sat)
        self.is_lightning = True
        self.is_lnurl = True  # `bool(self.lnurl_data)` should be equivalent, this is only here as it is a kivy Property

    def update(self):
        if self.app.wallet is None:
            return
        _list = self.app.wallet.get_unpaid_invoices()
        _list.reverse()
        payments_container = self.ids.payments_container
        payments_container.data = [self.get_card(invoice) for invoice in _list]

    def update_item(self, key, invoice):
        payments_container = self.ids.payments_container
        data = payments_container.data
        for item in data:
            if item['key'] == key:
                item.update(self.get_card(invoice))
        payments_container.data = data
        payments_container.refresh_from_data()

    def show_item(self, obj):
        self.app.show_invoice(obj.key)

    def get_card(self, item: Invoice) -> Dict[str, Any]:
        status = self.app.wallet.get_invoice_status(item)
        status_str = item.get_status_str(status)
        is_lightning = item.is_lightning()
        key = item.get_id()
        if is_lightning:
            address = item.rhash
            if self.app.wallet.lnworker:
                log = self.app.wallet.lnworker.logs.get(key)
                if status == PR_INFLIGHT and log:
                    status_str += '... (%d)'%len(log)
            is_bip70 = False
        else:
            address = item.get_address()
            is_bip70 = bool(item.bip70)
        return {
            'is_lightning': is_lightning,
            'is_bip70': is_bip70,
            'screen': self,
            'status': status,
            'status_str': status_str,
            'key': key,
            'memo': item.message or _('No Description'),
            'address': address,
            'amount': self.app.format_amount_and_units(item.get_amount_sat() or 0),
        }

    def do_clear(self):
        self.amount = ''
        self.message = ''
        self.address = ''
        self.payment_request = None
        self.is_lightning = False
        self.is_bip70 = False
        self.parsed_URI = None
        self.is_max = False
        self.lnurl_data = None
        self.is_lnurl = False

    def set_request(self, pr: 'PaymentRequest'):
        self.address = pr.get_requestor()
        amount = pr.get_amount()
        self.amount = self.app.format_amount_and_units(amount) if amount else ''
        self.message = pr.get_memo()
        self.locked = True
        self.payment_request = pr

    def do_paste(self):
        data = self.app._clipboard.paste().strip()
        if not data:
            self.app.show_info(_("Clipboard is empty"))
            return
        self.app.on_data_input(data)

    def read_invoice(self):
        address = str(self.address)
        if not address:
            self.app.show_error(_('Recipient not specified.') + ' ' + _('Please scan a Dogecoin address or a payment request'))
            return
        if not self.amount:
            self.app.show_error(_('Please enter an amount'))
            return
        if self.is_max:
            amount_sat = '!'
        else:
            try:
                amount_sat = self.app.get_amount(self.amount)
            except:
                self.app.show_error(_('Invalid amount') + ':\n' + self.amount)
                return
        message = self.message
        try:
            if self.is_lightning:
                assert type(amount_sat) is int
                invoice = Invoice.from_bech32(address)
                if invoice.amount_msat is None:
                    invoice.amount_msat = int(amount_sat * 1000)
                return invoice
            else:
                # on-chain
                if self.payment_request:
                    outputs = self.payment_request.get_outputs()
                else:
                    if not bitcoin.is_address(address):
                        self.app.show_error(_('Invalid Dogecoin Address') + ':\n' + address)
                        return
                    outputs = [PartialTxOutput.from_address_and_value(address, amount_sat)]
                return self.app.wallet.create_invoice(
                    outputs=outputs,
                    message=message,
                    pr=self.payment_request,
                    URI=self.parsed_URI)
        except InvoiceError as e:
            self.app.show_error(_('Error creating payment') + ':\n' + str(e))

    def do_save(self):
        invoice = self.read_invoice()
        if not invoice:
            return
        self.save_invoice(invoice)

    def save_invoice(self, invoice):
        self.app.wallet.save_invoice(invoice)
        self.do_clear()
        self.update()

    def _lnurl_get_invoice(self) -> None:
        assert self.lnurl_data
        try:
            amount = self.app.get_amount(self.amount)
        except:
            self.app.show_error(_('Invalid amount') + ':\n' + self.amount)
            return
        if not (self.lnurl_data.min_sendable_sat <= amount <= self.lnurl_data.max_sendable_sat):
            self.app.show_error(f'Amount must be between {self.lnurl_data.min_sendable_sat} and {self.lnurl_data.max_sendable_sat} sat.')
            return
        try:
            # FIXME network request blocking GUI thread:
            invoice_data = Network.run_from_another_thread(callback_lnurl(
                self.lnurl_data.callback_url,
                params={'amount': amount * 1000},
            ))
        except LNURLError as e:
            self.app.show_error(f"LNURL request encountered error: {e}")
            self.do_clear()
            return
        invoice = invoice_data.get('pr')
        self.set_bolt11(invoice)
        self.lnurl_data = None
        self.is_lnurl = False

    def do_pay(self):
        if self.lnurl_data:
            self._lnurl_get_invoice()
            return
        invoice = self.read_invoice()
        if not invoice:
            return
        self.do_pay_invoice(invoice)

    def do_pay_invoice(self, invoice):
        if invoice.is_lightning():
            if self.app.wallet.lnworker:
                amount_sat = invoice.get_amount_sat()
                msg = _("Pay lightning invoice?") + '\n\n' + _("This will send {}?").format(self.app.format_amount_and_units_with_fiat(amount_sat)) +'\n'
                self.app.protected(msg, self._do_pay_lightning, (invoice,))
            else:
                self.app.show_error(_("Lightning payments are not available for this wallet"))
        else:
            self._do_pay_onchain(invoice)

    def _do_pay_lightning(self, invoice: Invoice, pw) -> None:
        amount_msat = invoice.get_amount_msat()
        def pay_thread():
            try:
                coro = self.app.wallet.lnworker.pay_invoice(invoice.lightning_invoice, amount_msat=amount_msat)
                fut = asyncio.run_coroutine_threadsafe(coro, self.app.network.asyncio_loop)
                fut.result()
            except Exception as e:
                self.app.show_error(repr(e))
        self.save_invoice(invoice)
        threading.Thread(target=pay_thread).start()

    def _do_pay_onchain(self, invoice: Invoice) -> None:
        outputs = invoice.outputs
        amount = sum(map(lambda x: x.value, outputs)) if not any(parse_max_spend(x.value) for x in outputs) else '!'
        coins = self.app.wallet.get_spendable_coins(None)
        make_tx = lambda: self.app.wallet.make_unsigned_transaction(coins=coins, outputs=outputs)
        on_pay = lambda tx: self.app.protected(_('Send payment?'), self.send_tx, (tx, invoice))
        d = ConfirmTxDialog(self.app, amount=amount, make_tx=make_tx, on_pay=on_pay)
        d.open()

    def send_tx(self, tx, invoice, password):
        if self.app.wallet.has_password() and password is None:
            return
        self.save_invoice(invoice)
        def on_success(tx):
            if tx.is_complete():
                self.app.broadcast(tx)
            else:
                self.app.tx_dialog(tx)
        def on_failure(error):
            self.app.show_error(error)
        if self.app.wallet.can_sign(tx):
            self.app.show_info("Signing...")
            self.app.sign_tx(tx, password, on_success, on_failure)
        else:
            self.app.tx_dialog(tx)


class ReceiveScreen(CScreen):

    kvname = 'receive'
    expiration_text = StringProperty('')

    def __init__(self, **kwargs):
        super(ReceiveScreen, self).__init__(**kwargs)
        Clock.schedule_interval(lambda dt: self.update(), 5)
        self.is_max = False # not used for receiving (see app.amount_dialog)
        self.expiration_text = pr_expiration_values[self.expiry()]

    def on_open(self):
        c = self.expiry()
        self.expiration_text = pr_expiration_values[c]

    def expiry(self):
        return self.app.electrum_config.get('request_expiry', PR_DEFAULT_EXPIRATION_WHEN_CREATING)

    def clear(self):
        self.address = ''
        self.amount = ''
        self.message = ''
        self.lnaddr = ''

    def set_address(self, addr):
        self.address = addr

    def on_address(self, addr):
        req = self.app.wallet.get_request_by_addr(addr)
        self.status = ''
        if req:
            self.message = req.get('memo', '')
            amount = req.get('amount')
            self.amount = self.app.format_amount_and_units(amount) if amount else ''
            status = req.get('status', PR_UNKNOWN)
            self.status = _('Payment received') if status == PR_PAID else ''

    def get_URI(self):
        from electrum.util import create_bip21_uri
        amount = self.app.get_amount(self.amount)
        return create_bip21_uri(self.address, amount, self.message)

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.copy(uri)
        self.app.show_info(_('Request copied to clipboard'))

    def new_request(self):
        amount_str = self.amount
        amount_sat = self.app.get_amount(amount_str) if amount_str else 0
        message = self.message
        expiry = self.expiry()
        if amount_sat and amount_sat < self.app.wallet.dust_threshold():
            self.address = ''
            if not self.app.wallet.has_lightning():
                self.app.show_info(_('Amount too small to be received onchain'))
                return
        else:
            addr = self.address or self.app.wallet.get_unused_address()
            if not addr:
                if not self.app.wallet.is_deterministic():
                    addr = self.app.wallet.get_receiving_address()
                else:
                    self.app.show_info(_('No address available. Please remove some of your pending requests.'))
                    return
            self.address = addr
        try:
            key = self.app.wallet.create_request(amount_sat, message, expiry, self.address)
        except InvoiceError as e:
            self.app.show_error(_('Error creating payment request') + ':\n' + str(e))
            return
        self.clear()
        self.update()
        self.app.show_request(key)

    def get_card(self, req: Invoice) -> Dict[str, Any]:
        is_lightning = req.is_lightning()
        if not is_lightning:
            address = req.get_address()
        else:
            address = req.lightning_invoice
        key = req.get_id()
        amount = req.get_amount_sat()
        description = req.message
        status = self.app.wallet.get_invoice_status(req)
        status_str = req.get_status_str(status)
        ci = {}
        ci['screen'] = self
        ci['address'] = address
        ci['is_lightning'] = is_lightning
        ci['key'] = key
        ci['amount'] = self.app.format_amount_and_units(amount) if amount else ''
        ci['memo'] = description or _('No Description')
        ci['status'] = status
        ci['status_str'] = status_str
        return ci

    def update(self):
        if self.app.wallet is None:
            return
        _list = self.app.wallet.get_unpaid_requests()
        _list.reverse()
        requests_container = self.ids.requests_container
        requests_container.data = [self.get_card(item) for item in _list]

    def update_item(self, key, request):
        payments_container = self.ids.requests_container
        data = payments_container.data
        for item in data:
            if item['key'] == key:
                status = self.app.wallet.get_invoice_status(request)
                status_str = request.get_status_str(status)
                item['status'] = status
                item['status_str'] = status_str
        payments_container.data = data # needed?
        payments_container.refresh_from_data()

    def show_item(self, obj):
        self.app.show_request(obj.key)

    def expiration_dialog(self, obj):
        from .dialogs.choice_dialog import ChoiceDialog
        def callback(c):
            self.app.electrum_config.set_key('request_expiry', c)
            self.expiration_text = pr_expiration_values[c]
        d = ChoiceDialog(_('Expiration date'), pr_expiration_values, self.expiry(), callback)
        d.open()


class TabbedCarousel(Factory.TabbedPanel):
    '''Custom TabbedPanel using a carousel used in the Main Screen
    '''

    carousel = ObjectProperty(None)

    def animate_tab_to_center(self, value):
        scrlv = self._tab_strip.parent
        if not scrlv:
            return
        idx = self.tab_list.index(value)
        n = len(self.tab_list)
        if idx in [0, 1]:
            scroll_x = 1
        elif idx in [n-1, n-2]:
            scroll_x = 0
        else:
            scroll_x = 1. * (n - idx - 1) / (n - 1)
        mation = Factory.Animation(scroll_x=scroll_x, d=.25)
        mation.cancel_all(scrlv)
        mation.start(scrlv)

    def on_current_tab(self, instance, value):
        self.animate_tab_to_center(value)

    def on_index(self, instance, value):
        current_slide = instance.current_slide
        if not hasattr(current_slide, 'tab'):
            return
        tab = current_slide.tab
        ct = self.current_tab
        try:
            if ct.text != tab.text:
                carousel = self.carousel
                carousel.slides[ct.slide].dispatch('on_leave')
                self.switch_to(tab)
                carousel.slides[tab.slide].dispatch('on_enter')
        except AttributeError:
            current_slide.dispatch('on_enter')

    def switch_to(self, header):
        # we have to replace the functionality of the original switch_to
        if not header:
            return
        if not hasattr(header, 'slide'):
            header.content = self.carousel
            super(TabbedCarousel, self).switch_to(header)
            try:
                tab = self.tab_list[-1]
            except IndexError:
                return
            self._current_tab = tab
            tab.state = 'down'
            return

        carousel = self.carousel
        self.current_tab.state = "normal"
        header.state = 'down'
        self._current_tab = header
        # set the carousel to load the appropriate slide
        # saved in the screen attribute of the tab head
        slide = carousel.slides[header.slide]
        if carousel.current_slide != slide:
            carousel.current_slide.dispatch('on_leave')
            carousel.load_slide(slide)
            slide.dispatch('on_enter')

    def add_widget(self, widget, index=0):
        if isinstance(widget, Factory.CScreen):
            self.carousel.add_widget(widget)
            return
        super(TabbedCarousel, self).add_widget(widget, index=index)
