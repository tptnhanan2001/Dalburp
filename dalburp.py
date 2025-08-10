# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
import subprocess, threading, json
from javax.swing import JPanel, JScrollPane, JTable, table, BoxLayout
from tempfile import NamedTemporaryFile

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    scanned_urls = set()

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Dalfox Auto Scan")
        callbacks.registerHttpListener(self)

        # UI table setup
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.columns = ["Method", "URL", "Status", "Payload", "Data"]
        self.table_model = table.DefaultTableModel([], self.columns)
        self.table = JTable(self.table_model)
        self.panel.add(JScrollPane(self.table))

        callbacks.addSuiteTab(self)
        print("[Dalfox] Extension loaded.")

    def getTabCaption(self):
        return "Dalfox Results"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        req_info = self.helpers.analyzeRequest(messageInfo)
        url = str(req_info.getUrl())
        method = req_info.getMethod()

        if (method, url) not in self.scanned_urls:
            self.scanned_urls.add((method, url))
            threading.Thread(target=self.run_dalfox, args=(method, url, messageInfo)).start()

    def run_dalfox(self, method, url, messageInfo):
        try:
            request_bytes = messageInfo.getRequest()
            request_str = self.helpers.bytesToString(request_bytes)

            parts = request_str.split("\r\n\r\n", 1)
            head = parts[0]
            body = parts[1] if len(parts) > 1 else ""

            host = ""
            for line in head.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            scheme = "https" if messageInfo.getHttpService().getProtocol() == "https" else "http"
            full_url = "{}://{}".format(scheme, host)

            req_line = head.split("\r\n")[0]
            path = req_line.split(" ", 2)[1]
            full_url = "{}{}".format(full_url, path)

            # Dalfox command
            if method.upper() == "GET":
                cmd = ["dalfox", "url", full_url, "--silence"]
            elif method.upper() == "GET":
                cmd = ["dalfox", "url", full_url, "-b", "http://ntxss.eovhlgrzqazlzchtkozbmw1qgwt0aako0.oast.fun" ,"--silence"]
            else:
                cmd = [
                    "dalfox", "url", full_url,
                    "--data", body,
                    "--method", method,
                     "-b", "http://ntxss.eovhlgrzqazlzchtkozbmw1qgwt0aako0.oast.fun" ,
                    "--silence"
                ]

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            output_text = out.decode("utf-8", errors="ignore").strip()

            vuln_found = False
            payload = ""

            if output_text.startswith("{") or output_text.startswith("["):
                try:
                    results = json.loads(output_text)
                    if "data" in results:
                        for item in results["data"]:
                            self.add_result(method, full_url, "VULNERABLE", item.get("payload", ""), body)
                        return
                except:
                    pass

            for line in output_text.splitlines():
                if "[POC]" in line or "[VULN]" in line:
                    vuln_found = True
                    payload = line.strip()
                    break

            if vuln_found:
                self.add_result(method, full_url, "VULNERABLE", payload, body)
            else:
                self.add_result(method, full_url, "No Vuln", "", body)

        except Exception as e:
            self.add_result(method, url, "Error", str(e), "")

    def add_result(self, method, url, status, payload, data):
        self.table_model.addRow([method, url, status, payload, data])
