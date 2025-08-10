# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab, IContextMenuFactory
import subprocess, json
from javax.swing import JPanel, JScrollPane, JTable, table, BoxLayout, JMenuItem
from java.util import ArrayList

class BurpExtender(IBurpExtender, IScannerCheck, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Dalfox Active Scan")
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # UI table setup
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.columns = ["Method", "URL", "Status", "Payload", "Data"]
        self.table_model = table.DefaultTableModel([], self.columns)
        self.table = JTable(self.table_model)
        self.panel.add(JScrollPane(self.table))

        callbacks.addSuiteTab(self)
        print("[Dalfox] Active Scan Extension with Context Menu loaded.")

    def getTabCaption(self):
        return "Dalfox Results"

    def getUiComponent(self):
        return self.panel

    # Context menu
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
                body = self.get_request_body(message, req_info)
                self.run_dalfox(method, url, body)

        except Exception as e:
            print("[Dalfox] Context Scan Error:", e)

    # Active scan logic
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            req_info = self.helpers.analyzeRequest(baseRequestResponse)
            url = str(req_info.getUrl())
            method = req_info.getMethod()
            body = self.get_request_body(baseRequestResponse, req_info)

            findings = self.run_dalfox(method, url, body)
            issues = []
            for finding in findings:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "Dalfox XSS",
                    "Possible XSS vulnerability detected.<br>Payload: <b>{}</b>".format(finding),
                    "High"
                ))
            return issues if issues else None

        except Exception as e:
            print("[Dalfox] ActiveScan Error:", e)
            return None

    def run_dalfox(self, method, url, body):
        try:
            if method.upper() == "GET":
                cmd = [
                    "dalfox", "url", url,
                    "-b", "http://ntxss.eovhlgrzqazlzchtkozbmw1qgwt0aako0.oast.fun",
                    "--silence"
                ]
            else:
                cmd = [
                    "dalfox", "url", url,
                    "--data", body,
                    "--method", method,
                    "-b", "http://ntxss.eovhlgrzqazlzchtkozbmw1qgwt0aako0.oast.fun",
                    "--silence"
                ]

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            output_text = out.decode("utf-8", errors="ignore").strip()

            payloads = []
            for line in output_text.splitlines():
                if "[POC]" in line or "[VULN]" in line:
                    payloads.append(line.strip())

            # Update UI table
            for p in payloads:
                self.table_model.addRow([method, url, "VULNERABLE", p, body])
            if not payloads:
                self.table_model.addRow([method, url, "No Vuln", "", body])

            return payloads

        except Exception as e:
            self.table_model.addRow([method, url, "Error", str(e), body])
            return []

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
