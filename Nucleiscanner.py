# -*- coding: utf-8 -*-

try:
    from burp import IBurpExtender, ITab, IScanIssue, IContextMenuFactory, IExtensionStateListener
    from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, EventQueue, Toolkit
    from java.awt.event import MouseAdapter
    from javax.swing import (JPanel, JLabel, JButton, JTextField, JTextArea, JScrollPane, JOptionPane,
                             JFileChooser, JMenuItem, JCheckBox, JTabbedPane, SwingConstants,
                             JComboBox, JTable, JPopupMenu)
    from javax.swing.border import EmptyBorder, TitledBorder
    from javax.swing.event import DocumentListener
    from javax.swing.table import DefaultTableModel, TableRowSorter, DefaultTableCellRenderer
    from javax.swing import RowFilter
    from java.net import URL, URI
    from java.util import ArrayList
    from java.awt.datatransfer import StringSelection
    from threading import Thread
    import subprocess
    import os
    import re
except ImportError as e:
    print(e)


class FieldListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def insertUpdate(self, event):
        self.callback()

    def removeUpdate(self, event):
        self.callback()

    def changedUpdate(self, event):
        self.callback()


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return ""

    def getRemediationBackground(self):
        return ""

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return ""

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


class VulnerabilityTableMouseListener(MouseAdapter):
    def __init__(self, parent):
        self.parent = parent

    def mouseReleased(self, event):
        if event.isPopupTrigger():
            table = event.getComponent()
            row = table.rowAtPoint(event.getPoint())
            if row < 0:
                return
            table.setRowSelectionInterval(row, row)
            popup = JPopupMenu()
            copyUrlItem = JMenuItem("Copy URL", actionPerformed=lambda e: self.parent.copyUrl(row))
            popup.add(copyUrlItem)
            copyDetailsItem = JMenuItem("Copy All Details", actionPerformed=lambda e: self.parent.copyDetails(row))
            popup.add(copyDetailsItem)
            deleteItem = JMenuItem("Delete Entry", actionPerformed=lambda e: self.parent.deleteVulnerability(row))
            popup.add(deleteItem)
            popup.show(table, event.getX(), event.getY())


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("NucleiScanner")
        self._helpers = callbacks.getHelpers()

        self.initUI()
        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerContextMenuFactory(self)
        self.loadConfig()

        # State variables for scanning
        self.isScanning = False
        self.scanThreads = []
        self.runningSubprocesses = set()

        print("Nuclei extension loaded successfully.")

    def initUI(self):
        # Main panel holding our tabbed pane
        self.mainPanel = JPanel(BorderLayout(10, 10))
        self.mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Create main tabbed pane: one for "Scan" and one for "Settings"
        self.mainTabbedPane = JTabbedPane()

        #####################
        # Build the SCAN tab
        #####################
        self.scanPanel = JPanel(BorderLayout())

        # --- Top panel: target and scan controls ---
        scanTopPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0
        gbc.gridy = 0
        scanTopPanel.add(JLabel("Target URL:"), gbc)

        gbc.gridx = 1
        self.targetField = JTextField('', 30)
        self.targetField.setToolTipText("Enter the target URL to scan")
        scanTopPanel.add(self.targetField, gbc)

        gbc.gridx = 2
        self.scanButton = JButton("Start Scan", actionPerformed=self.startScan)
        scanTopPanel.add(self.scanButton, gbc)

        gbc.gridx = 3
        self.stopButton = JButton("Stop Scan", actionPerformed=self.stopScan)
        self.stopButton.setEnabled(False)
        scanTopPanel.add(self.stopButton, gbc)

        self.scanPanel.add(scanTopPanel, BorderLayout.NORTH)

        # --- Bottom panel: Nested tabbed pane for Scan Log and Vulnerabilities ---
        self.resultTabbedPane = JTabbedPane()

        # Scan Log tab (enhanced UI)
        self.scanLogPanel = JPanel(BorderLayout())
        self.scanLogPanel.setBorder(TitledBorder("Scan Log"))
        self.resultsArea = JTextArea()
        self.resultsArea.setEditable(False)
        self.resultsArea.setLineWrap(True)
        self.resultsArea.setWrapStyleWord(True)
        scanLogScrollPane = JScrollPane(self.resultsArea)
        self.scanLogPanel.add(scanLogScrollPane, BorderLayout.CENTER)
        self.resultTabbedPane.addTab("Scan Log", self.scanLogPanel)

        # Vulnerabilities tab: table-based UI with filtering and extra buttons.
        self.vulnPanel = JPanel(BorderLayout())
        self.vulnPanel.setBorder(TitledBorder("Vulnerabilities"))

        # Create a filter panel with a severity combo box and additional buttons.
        filterPanel = JPanel()
        filterPanel.add(JLabel("Filter by Severity:"))
        self.filterCombo = JComboBox(["All", "Critical", "High", "Medium", "Low", "Info"])
        filterPanel.add(self.filterCombo)

        # Add Clear Vulnerabilities button.
        self.clearButton = JButton("Clear Vulnerabilities", actionPerformed=self.clearVulnerabilities)
        filterPanel.add(self.clearButton)

        # Add Import Vulnerabilities button.
        self.importButton = JButton("Import Vulnerabilities", actionPerformed=self.importVulnerabilities)
        filterPanel.add(self.importButton)

        # Add Export Vulnerabilities button.
        self.exportButton = JButton("Export Vulnerabilities", actionPerformed=self.exportVulnerabilities)
        filterPanel.add(self.exportButton)

        # Add Delete Selected button.
        self.deleteSelectedButton = JButton("Delete Selected", actionPerformed=self.deleteSelectedVulnerabilities)
        filterPanel.add(self.deleteSelectedButton)

        # Create a table model with four columns: Template, Protocol, Severity, URL.
        self.vulnTableModel = DefaultTableModel(["Template", "Protocol", "Severity", "URL"], 0)
        self.vulnTable = JTable(self.vulnTableModel)
        self.vulnTable.setFillsViewportHeight(True)

        # Use a TableRowSorter to allow filtering.
        self.vulnSorter = TableRowSorter(self.vulnTableModel)
        self.vulnTable.setRowSorter(self.vulnSorter)

        # Center the content of all cells.
        renderer = DefaultTableCellRenderer()
        renderer.setHorizontalAlignment(SwingConstants.CENTER)
        for i in range(self.vulnTable.getColumnCount()):
            self.vulnTable.getColumnModel().getColumn(i).setCellRenderer(renderer)

        # Optional: set column widths for a better look.
        self.vulnTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.vulnTable.getColumnModel().getColumn(1).setPreferredWidth(80)
        self.vulnTable.getColumnModel().getColumn(2).setPreferredWidth(80)
        self.vulnTable.getColumnModel().getColumn(3).setPreferredWidth(300)

        # Define the filter update function.
        def updateFilter(event=None):
            selected = self.filterCombo.getSelectedItem().lower()
            if selected == "all":
                self.vulnSorter.setRowFilter(None)
            else:
                # The severity is in the third column (index 2).
                self.vulnSorter.setRowFilter(RowFilter.regexFilter("(?i)^" + selected + "$", 2))
        self.filterCombo.addActionListener(updateFilter)

        vulnTableScrollPane = JScrollPane(self.vulnTable)
        self.vulnPanel.add(filterPanel, BorderLayout.NORTH)
        self.vulnPanel.add(vulnTableScrollPane, BorderLayout.CENTER)

        self.resultTabbedPane.addTab("Vulnerabilities", self.vulnPanel)
        self.scanPanel.add(self.resultTabbedPane, BorderLayout.CENTER)

        ########################
        # Build the SETTINGS tab
        ########################
        self.settingsPanel = JPanel(GridBagLayout())
        self.settingsPanel.setBorder(EmptyBorder(10, 10, 10, 10))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.NORTHWEST
        row = 0

        # Nuclei binary path
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Nuclei Path:"), gbc)
        gbc.gridx = 1
        self.nucleiPathField = JTextField('', 30)
        self.nucleiPathField.setToolTipText("Path to the Nuclei binary")
        self.settingsPanel.add(self.nucleiPathField, gbc)
        gbc.gridx = 2
        self.browseNucleiButton = JButton("Browse", actionPerformed=self.browseNucleiPath)
        self.settingsPanel.add(self.browseNucleiButton, gbc)
        row += 1

        # Templates path
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Templates Path:"), gbc)
        gbc.gridx = 1
        self.templatesPathField = JTextField('', 30)
        self.templatesPathField.setToolTipText("Path to the Nuclei templates directory")
        self.settingsPanel.add(self.templatesPathField, gbc)
        gbc.gridx = 2
        self.browseTemplatesButton = JButton("Browse", actionPerformed=self.browseTemplatesPath)
        self.settingsPanel.add(self.browseTemplatesButton, gbc)
        row += 1

        # Custom Arguments
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Custom Arguments:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.customArgsField = JTextField('', 30)
        self.customArgsField.setToolTipText("Additional Nuclei command-line arguments")
        self.settingsPanel.add(self.customArgsField, gbc)
        gbc.gridwidth = 1
        row += 1

        # Verbosity dropdown
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Verbosity:"), gbc)
        gbc.gridx = 1
        self.verbosityDropdown = JComboBox(["Default", "Verbose", "Very Verbose"])
        self.verbosityDropdown.setToolTipText("Select verbosity level")
        self.settingsPanel.add(self.verbosityDropdown, gbc)
        row += 1

        # Severity Dropdown
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Severity (-severity):"), gbc)
        gbc.gridx = 1
        self.severityDropdown = JComboBox(["", "info", "low", "medium", "high", "critical", "unknown"])
        self.severityDropdown.setToolTipText("Select severity to include")
        self.settingsPanel.add(self.severityDropdown, gbc)
        row += 1

        # Proxy
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Proxy (-proxy):"), gbc)
        gbc.gridx = 1
        self.proxyField = JTextField('', 30)
        self.proxyField.setToolTipText("Proxy server (e.g., socks5://127.0.0.1:8080)")
        self.settingsPanel.add(self.proxyField, gbc)
        row += 1

        # Checkboxes for additional options
        gbc.gridx = 0
        gbc.gridy = row
        self.newTemplatesCheckbox = JCheckBox("Run only New Templates (-nt)")
        self.newTemplatesCheckbox.setToolTipText("Include only new templates added in the latest release")
        self.settingsPanel.add(self.newTemplatesCheckbox, gbc)
        gbc.gridx = 1
        self.autoScanCheckbox = JCheckBox("Automatic Scan (-as)")
        self.autoScanCheckbox.setToolTipText("Enable automatic scanning with technology detection")
        self.settingsPanel.add(self.autoScanCheckbox, gbc)
        row += 1

        # Rate Limit (-rl)
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Rate Limit:"), gbc)
        gbc.gridx = 1
        self.rateLimitField = JTextField('', 10)
        self.rateLimitField.setToolTipText("Maximum requests per second")
        self.settingsPanel.add(self.rateLimitField, gbc)
        row += 1

        # Concurrency (-c)
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Concurrency:"), gbc)
        gbc.gridx = 1
        self.concurrencyField = JTextField('', 10)
        self.concurrencyField.setToolTipText("Number of concurrent threads")
        self.settingsPanel.add(self.concurrencyField, gbc)
        row += 1

        # Tags (-tags)
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Tags:"), gbc)
        gbc.gridx = 1
        self.tagsField = JTextField('', 30)
        self.tagsField.setToolTipText("Comma-separated list of template tags to include")
        self.settingsPanel.add(self.tagsField, gbc)
        row += 1

        # Headers (-H)
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Headers:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.headersArea = JTextArea(5, 30)
        self.headersArea.setToolTipText("Custom headers (one per line)")
        headersScrollPane = JScrollPane(self.headersArea)
        self.settingsPanel.add(headersScrollPane, gbc)
        gbc.gridwidth = 1
        row += 1

        # Command Preview
        gbc.gridx = 0
        gbc.gridy = row
        self.settingsPanel.add(JLabel("Command:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.commandPreviewArea = JTextArea(3, 50)
        self.commandPreviewArea.setToolTipText("Modify the command as needed")
        commandScrollPane = JScrollPane(self.commandPreviewArea)
        self.settingsPanel.add(commandScrollPane, gbc)
        gbc.gridwidth = 1
        gbc.gridx = 3
        self.resetButton = JButton("Reset Command", actionPerformed=self.resetCommand)
        self.settingsPanel.add(self.resetButton, gbc)
        row += 1

        settingsScrollPane = JScrollPane(self.settingsPanel)

        # Add the Scan and Settings tabs.
        self.mainTabbedPane.addTab("Scan", self.scanPanel)
        self.mainTabbedPane.addTab("Settings", settingsScrollPane)

        self.mainPanel.add(self.mainTabbedPane, BorderLayout.CENTER)
        self._callbacks.addSuiteTab(self)

        # Register document listeners to update command preview.
        self.targetField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.nucleiPathField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.templatesPathField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.customArgsField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.rateLimitField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.concurrencyField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.tagsField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.headersArea.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.commandPreviewArea.getDocument().addDocumentListener(FieldListener(self.commandEdited))
        self.severityDropdown.addActionListener(self.updateCommandPreview)
        self.proxyField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.verbosityDropdown.addActionListener(self.updateCommandPreview)

        self.updateCommandPreview()

        # Add right-click context menu support to the vulnerabilities table.
        self.vulnTable.addMouseListener(VulnerabilityTableMouseListener(self))

    def getTabCaption(self):
        return "NucleiScanner"

    def getUiComponent(self):
        return self.mainPanel

    def loadConfig(self):
        # Automatic path detection for Nuclei binary.
        nuclei_paths = [
            '/usr/bin/nuclei',
            '/usr/local/bin/nuclei',
            os.path.expanduser('~/go/bin/nuclei'),
            os.path.expanduser('~/.pdtm/go/bin/nuclei')
        ]
        found_nuclei = False
        for path in nuclei_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self.nucleiPathField.setText(path)
                found_nuclei = True
                break
        if not found_nuclei:
            saved_path = self._callbacks.loadExtensionSetting("nucleiPath")
            if saved_path:
                self.nucleiPathField.setText(saved_path)

        # Automatic path detection for Nuclei templates.
        templates_path = os.path.expanduser('~/nuclei-templates')
        if os.path.isdir(templates_path):
            self.templatesPathField.setText(templates_path)
        else:
            saved_templates = self._callbacks.loadExtensionSetting("templatesPath")
            if saved_templates:
                self.templatesPathField.setText(saved_templates)

        def load_setting(field, key):
            val = self._callbacks.loadExtensionSetting(key)
            if val:
                field.setText(val)

        load_setting(self.customArgsField, "customArgs")
        load_setting(self.proxyField, "proxy")
        load_setting(self.rateLimitField, "rateLimit")
        load_setting(self.concurrencyField, "concurrency")
        load_setting(self.tagsField, "tags")
        headers_val = self._callbacks.loadExtensionSetting("headers")
        if headers_val:
            self.headersArea.setText(headers_val)

        newTemplates_val = self._callbacks.loadExtensionSetting("newTemplates")
        if newTemplates_val:
            self.newTemplatesCheckbox.setSelected(newTemplates_val == 'True')
        autoScan_val = self._callbacks.loadExtensionSetting("autoScan")
        if autoScan_val:
            self.autoScanCheckbox.setSelected(autoScan_val == 'True')
        severity_val = self._callbacks.loadExtensionSetting("severity")
        if severity_val:
            self.severityDropdown.setSelectedItem(severity_val)
        last_cmd = self._callbacks.loadExtensionSetting("lastCommand")
        if last_cmd:
            self.commandPreviewArea.setText(last_cmd)

    def saveConfig(self):
        self._callbacks.saveExtensionSetting("nucleiPath", self.nucleiPathField.getText())
        self._callbacks.saveExtensionSetting("templatesPath", self.templatesPathField.getText())
        self._callbacks.saveExtensionSetting("customArgs", self.customArgsField.getText())
        self._callbacks.saveExtensionSetting("proxy", self.proxyField.getText())
        self._callbacks.saveExtensionSetting("rateLimit", self.rateLimitField.getText())
        self._callbacks.saveExtensionSetting("concurrency", self.concurrencyField.getText())
        self._callbacks.saveExtensionSetting("tags", self.tagsField.getText())
        self._callbacks.saveExtensionSetting("headers", self.headersArea.getText())
        self._callbacks.saveExtensionSetting("newTemplates", str(self.newTemplatesCheckbox.isSelected()))
        self._callbacks.saveExtensionSetting("autoScan", str(self.autoScanCheckbox.isSelected()))
        self._callbacks.saveExtensionSetting("severity", self.severityDropdown.getSelectedItem())
        self._callbacks.saveExtensionSetting("lastCommand", self.commandPreviewArea.getText())

    def extensionUnloaded(self):
        self.saveConfig()
        self.stopAllScans()
        print("Nuclei extension unloaded.")

    def startScan(self, event):
        target = self.targetField.getText().strip()
        if not target:
            JOptionPane.showMessageDialog(self.mainPanel, "Please enter a target URL.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        nuclei_path = self.nucleiPathField.getText().strip()
        if not nuclei_path or not os.path.isfile(nuclei_path) or not os.access(nuclei_path, os.X_OK):
            JOptionPane.showMessageDialog(self.mainPanel, "Invalid Nuclei path.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        self.isScanning = True
        self.scanButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.appendResult("Starting new scan...\n")
        # Optionally, clear the vulnerabilities table (or let the user do it with the Clear button)
        # self.clearVulnerabilities(None)

        cmd = self.commandPreviewArea.getText().strip()
        if not cmd:
            JOptionPane.showMessageDialog(self.mainPanel, "Command is empty. Please specify a command.", "Error", JOptionPane.ERROR_MESSAGE)
            self.isScanning = False
            self.scanButton.setEnabled(True)
            self.stopButton.setEnabled(False)
            return

        cmd = cmd.replace('{target}', target)
        cmd_list = cmd.split()
        scanThread = Thread(target=self.runNucleiScan, args=(cmd_list,))
        scanThread.start()
        self.scanThreads.append(scanThread)

    def stopScan(self, event):
        self.stopAllScans()

    def stopAllScans(self):
        for p in list(self.runningSubprocesses):
            try:
                p.terminate()
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
            self.runningSubprocesses.remove(p)
        self.isScanning = False
        self.scanButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def runNucleiScan(self, cmd):
        self.appendResult("Executed command: {}\n".format(' '.join(cmd)))
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       bufsize=1, universal_newlines=True)
            self.runningSubprocesses.add(process)
            ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
            for line in iter(process.stdout.readline, ''):
                if not self.isScanning:
                    break
                line_clean = ansi_escape.sub('', line)
                self.appendResult(line_clean)
                self.handleNucleiResult(line_clean.strip())
            process.stdout.close()
            process.wait()
            if process in self.runningSubprocesses:
                self.runningSubprocesses.remove(process)
            if self.isScanning:
                self.appendResult("\nScan completed.\n")
            else:
                self.appendResult("\nScan stopped.\n")
        except Exception as e:
            self.appendResult("Error during scan: {}\n".format(str(e)))
        finally:
            self.isScanning = False
            self.scanButton.setEnabled(True)
            self.stopButton.setEnabled(False)

    def handleNucleiResult(self, result):
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        line = ansi_escape.sub('', result).strip()

        # Expected result format: [Template] [Protocol] [Severity] URL
        pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[(critical|high|medium|low|info)\]\s+(.*)$'
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            template = match.group(1).strip()
            protocol = match.group(2).strip()
            severity = match.group(3).lower().strip()
            url_str = match.group(4).strip()

            # Prevent duplicate vulnerabilities.
            if not self.isDuplicateVuln(template, protocol, severity, url_str):
                self.vulnTableModel.addRow([template, protocol, severity, url_str])
        else:
            self.appendResult(line + "\n")

    def isDuplicateVuln(self, template, protocol, severity, url_str):
        rowCount = self.vulnTableModel.getRowCount()
        for row in range(rowCount):
            existing_template = self.vulnTableModel.getValueAt(row, 0)
            existing_protocol = self.vulnTableModel.getValueAt(row, 1)
            existing_severity = self.vulnTableModel.getValueAt(row, 2)
            existing_url = self.vulnTableModel.getValueAt(row, 3)
            if (existing_template == template and 
                existing_protocol == protocol and 
                existing_severity == severity and 
                existing_url == url_str):
                return True
        return False

    def appendResult(self, text):
        def update():
            self.resultsArea.append(text)
            self.resultsArea.setCaretPosition(self.resultsArea.getDocument().getLength())
        EventQueue.invokeLater(update)

    def clearVulnerabilities(self, event):
        # Clears all vulnerabilities from the table.
        self.vulnTableModel.setRowCount(0)

    def importVulnerabilities(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Vulnerabilities")
        ret = chooser.showOpenDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            try:
                with open(file.getAbsolutePath(), "r") as f:
                    for line in f:
                        line = line.strip()
                        # Use the same pattern as for scan output.
                        pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[(critical|high|medium|low|info)\]\s+(.*)$'
                        match = re.match(pattern, line, re.IGNORECASE)
                        if match:
                            template = match.group(1).strip()
                            protocol = match.group(2).strip()
                            severity = match.group(3).lower().strip()
                            url_str = match.group(4).strip()
                            if not self.isDuplicateVuln(template, protocol, severity, url_str):
                                self.vulnTableModel.addRow([template, protocol, severity, url_str])
                self.appendResult("Vulnerabilities imported from file: {}\n".format(file.getAbsolutePath()))
            except Exception as e:
                self.appendResult("Error importing vulnerabilities: {}\n".format(str(e)))

    def exportVulnerabilities(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Vulnerabilities")
        ret = chooser.showSaveDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            try:
                with open(file.getAbsolutePath(), "w") as f:
                    rowCount = self.vulnTableModel.getRowCount()
                    for row in range(rowCount):
                        template = self.vulnTableModel.getValueAt(row, 0)
                        protocol = self.vulnTableModel.getValueAt(row, 1)
                        severity = self.vulnTableModel.getValueAt(row, 2)
                        url = self.vulnTableModel.getValueAt(row, 3)
                        # Format each vulnerability in plain text.
                        f.write("[{}] [{}] [{}] {}\n".format(template, protocol, severity, url))
                self.appendResult("Vulnerabilities exported to file: {}\n".format(file.getAbsolutePath()))
            except Exception as e:
                self.appendResult("Error exporting vulnerabilities: {}\n".format(str(e)))

    def deleteSelectedVulnerabilities(self, event):
        # Delete all selected rows.
        selectedRows = self.vulnTable.getSelectedRows()
        if selectedRows is None or len(selectedRows) == 0:
            return
        # Remove rows in reverse order.
        for i in sorted(selectedRows, reverse=True):
            modelRow = self.vulnTable.convertRowIndexToModel(i)
            self.vulnTableModel.removeRow(modelRow)
        self.appendResult("Deleted selected vulnerabilities.\n")

    def deleteVulnerability(self, row):
        # Delete a single vulnerability row (used in the context menu).
        model_row = self.vulnTable.convertRowIndexToModel(row)
        self.vulnTableModel.removeRow(model_row)
        self.appendResult("Deleted vulnerability at row {}.\n".format(model_row))

    def browseNucleiPath(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        ret = chooser.showOpenDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.nucleiPathField.setText(file.getAbsolutePath())
            self.updateCommandPreview()

    def browseTemplatesPath(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES)
        ret = chooser.showOpenDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            directory = chooser.getSelectedFile()
            self.templatesPathField.setText(directory.getAbsolutePath())
            self.updateCommandPreview()

    def createMenuItems(self, invocation):
        menu = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages:
            menuItem = JMenuItem("Send to NucleiScanner", actionPerformed=lambda x, inv=invocation: self.sendToNuclei(inv))
            menu.add(menuItem)
        if menu.size() == 0:
            return None
        return menu

    def sendToNuclei(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            requestInfo = self._helpers.analyzeRequest(messages[0])
            url = requestInfo.getUrl()
            self.targetField.setText(str(url))
            headers = requestInfo.getHeaders()
            if headers and len(headers) > 1:
                headers_text = '\n'.join(headers[1:])
                self.headersArea.setText(headers_text)
            else:
                self.headersArea.setText('')
            self.updateCommandPreview()

    def updateCommandPreview(self, event=None):
        target = '{target}'
        cmd = [self.nucleiPathField.getText().strip() or 'nuclei', '-u', target]

        templates_path = self.templatesPathField.getText().strip()
        if templates_path:
            cmd.extend(['-t', templates_path])
        custom_args = self.customArgsField.getText().strip()
        if custom_args:
            cmd.extend(custom_args.split())
        if self.newTemplatesCheckbox.isSelected():
            cmd.append('-nt')
        if self.autoScanCheckbox.isSelected():
            cmd.append('-as')
        severity = self.severityDropdown.getSelectedItem()
        if severity:
            cmd.extend(['-s', severity])
        rate_limit = self.rateLimitField.getText().strip()
        if rate_limit:
            cmd.extend(['-rl', rate_limit])
        concurrency = self.concurrencyField.getText().strip()
        if concurrency:
            cmd.extend(['-c', concurrency])
        tags = self.tagsField.getText().strip()
        if tags:
            cmd.extend(['-tags', tags])
        headers = self.headersArea.getText().strip()
        if headers:
            for header in headers.split('\n'):
                header = header.strip()
                if header:
                    cmd.extend(['-H', header])
        proxy = self.proxyField.getText().strip()
        if proxy:
            cmd.extend(['-proxy', proxy])
        verbosity = self.verbosityDropdown.getSelectedItem()
        if verbosity == "Verbose":
            cmd.append("-v")
        elif verbosity == "Very Verbose":
            cmd.append("-vv")

        self.commandPreviewArea.setText(' '.join(cmd))

    def commandEdited(self, event=None):
        pass

    def resetCommand(self, event):
        self.updateCommandPreview()