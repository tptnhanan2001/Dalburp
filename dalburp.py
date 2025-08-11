# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab, IContextMenuFactory
import subprocess, threading
from javax.swing import JPanel, JScrollPane, JTable, BoxLayout, JMenuItem
from javax.swing.table import DefaultTableModel
from java.util import ArrayList

class BurpExtender(IBurpExtender, IScannerCheck, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Dalfox Active Scan")
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # UI table setup: Method, URL, Status, Payload, Data, Cookie/Auth
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.columns = ["Method", "URL", "Status", "Payload", "Data", "Cookie", "Authorization"]
        self.table_model = DefaultTableModel([], self.columns)
        self.table = JTable(self.table_model)
        self.panel.add(JScrollPane(self.table))

        callbacks.addSuiteTab(self)
        print("[Dalfox] Active Scan Extension with Context Menu loaded.")

    def getTabCaption(self):
        return "Dalfox Results"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Dalfox Active Scan", actionPerformed=lambda x: self.context_scan(invocation))
        menu_list.add(menu_item)
        return menu_list

    def context_scan(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                return

            for message in selected_messages:
                req_info = self.helpers.analyzeRequest(message)
                url = str(req_info.getUrl())
                method = req_info.getMethod()
                headers = req_info.getHeaders()
                body = self.get_request_body(message, req_info)

                # Extract specific headers
                cookie_header = ""
                auth_header = ""
                header_list = []
                for h in headers:
                    if ":" in h and not h.lower().startswith("host:"):
                        header_list.append(h)
                        if h.lower().startswith("cookie:"):
                            cookie_header = h.split(":", 1)[1].strip()
                        if h.lower().startswith("authorization:"):
                            auth_header = h.split(":", 1)[1].strip()

                t = threading.Thread(target=self.run_dalfox, args=(method, url, body, header_list, cookie_header, auth_header))
                t.start()

        except Exception as e:
            print("[Dalfox] Context Scan Error:", e)

    def run_dalfox(self, method, url, body, headers=None, cookie="", auth=""):
        try:
            cmd = ["dalfox", "url", url, "--silence"]

            if headers:
                for h in headers:
                    cmd.extend(["-H", h])

            if method and method.upper() != "GET":
                cmd.extend(["--data", body or "", "--method", method])

            print("[Dalfox] Running: " + " ".join(cmd))
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            output_text = out.decode("utf-8", errors="ignore").strip()

            payloads = [line.strip() for line in output_text.splitlines() if "[POC]" in line or "[VULN]" in line]
            status = "VULNERABLE" if payloads else "No Vuln"

            if payloads:
                for p in payloads:
                    self.table_model.addRow([method, url, status, p, body, cookie, auth])
            else:
                self.table_model.addRow([method, url, status, "", body, cookie, auth])

        except Exception as e:
            self.table_model.addRow([method, url, "Error", str(e), body, cookie, auth])

    def get_request_body(self, baseRequestResponse, req_info):
        request_bytes = baseRequestResponse.getRequest()
        body_offset = req_info.getBodyOffset()
        return self.helpers.bytesToString(request_bytes)[body_offset:]


# Custom issue class
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
