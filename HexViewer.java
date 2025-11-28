//Simple HexViewer for Ghidra
//@author P0k000
//@category View
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
 
import java.nio.charset.StandardCharsets;
import javax.swing.table.TableColumn;
import javax.swing.table.TableCellRenderer;
import java.awt.event.KeyEvent;
import java.awt.event.InputEvent;
import java.awt.datatransfer.StringSelection;
import javax.swing.AbstractAction;


public class HexViewer extends GhidraScript {

    private JFrame frame;
    private JTable table;
    private DefaultTableModel tableModel;
    private int perLine = 16;
    private int modelPerLine = 16;
    private JTextField startField;
    private JTextField lengthField;
    private JLabel statusLabel;
    private JComboBox<Integer> bytesPerRowCombo;
    private JButton autoScaleBtn;
    private JTextField searchField;
    private JButton findNextBtn;
    private JButton findPrevBtn;
    // when loading multiple blocks we concatenate into this
    private List<Long> blockStartOffsets = new ArrayList<>();
    private List<Integer> blockLengths = new ArrayList<>();
    private byte[] originalCombined = new byte[0];
    // reuse compiled pattern to avoid repeated compilation / stack issues
    private static final java.util.regex.Pattern HEX_PAIR_PATTERN = java.util.regex.Pattern.compile("([0-9A-Fa-f]{2})");

    @Override
    public void run() throws Exception {
        SwingUtilities.invokeLater(() -> buildGui());
    }

    private void buildGui() {
        frame = new JFrame("Ghidra Hex Viewer : " + currentProgram.getName());
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Start (hex):"));
        startField = new JTextField(16);
        startField.setText(currentProgram.getImageBase().toString());
        top.add(startField);
        top.add(new JLabel("Length (dec):"));
        lengthField = new JTextField(8);
        lengthField.setText("all");
        top.add(lengthField);

        JButton loadBtn = new JButton("Load");
        JButton exportBtn = new JButton("Export to File");
        JButton importBtn = new JButton("Import from File");

        top.add(loadBtn);
        top.add(exportBtn);
        top.add(importBtn);

        top.add(new JLabel("Bytes/row:"));
        Integer[] options = new Integer[] {8, 16, 24, 32, 64};
        bytesPerRowCombo = new JComboBox<>(options);
        bytesPerRowCombo.setSelectedItem(perLine);
        top.add(bytesPerRowCombo);
        autoScaleBtn = new JButton("Auto-scale Columns");
        top.add(autoScaleBtn);

        frame.add(top, BorderLayout.NORTH);

        // initial table build (may be rebuilt on load to match data size)
        table = new JTable();
        rebuildTableModel(perLine);

        JScrollPane scroll = new JScrollPane(table);
        frame.add(scroll, BorderLayout.CENTER);

        // search bar
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchField = new JTextField(24);
        findPrevBtn = new JButton("Find Prev");
        findNextBtn = new JButton("Find Next");
        searchPanel.add(new JLabel("Search:"));
        searchPanel.add(searchField);
        searchPanel.add(findPrevBtn);
        searchPanel.add(findNextBtn);

        JPanel south = new JPanel(new BorderLayout());
        statusLabel = new JLabel("Ready");
        south.add(statusLabel, BorderLayout.WEST);
        south.add(searchPanel, BorderLayout.EAST);
        frame.add(south, BorderLayout.SOUTH);

        loadBtn.addActionListener(e -> loadMemory());
        exportBtn.addActionListener(e -> exportToFile());
        importBtn.addActionListener(e -> importFromFile());
        findNextBtn.addActionListener(e -> doFind(true));
        findPrevBtn.addActionListener(e -> doFind(false));

        bytesPerRowCombo.addActionListener(e -> {
            try {
                Integer v = (Integer) bytesPerRowCombo.getSelectedItem();
                if (v != null && v > 0) {
                    perLine = v;
                    rebuildTableModel(perLine);
                    populateTableFromCombined();
                    autosizeColumns();
                }
            } catch (Exception ex) {
                statusLabel.setText("Error setting bytes/row: " + ex.getMessage());
            }
        });

        autoScaleBtn.addActionListener(e -> autosizeColumns());

        // auto-load all memory at startup
        SwingUtilities.invokeLater(() -> {
            lengthField.setText("all");
            loadMemory();
        });

        frame.setSize(900, 600);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private Address parseHexAddress(String text) throws Exception {
        // Accept formats like 0x1000 or IMAGE_BASE or plain hex
        text = text.trim();
        if (text.startsWith("0x") || text.startsWith("0X")) {
            text = text.substring(2);
        }
        // If it's an address like "0x00400000" or decimal number
        long offset = Long.parseLong(text, 16);
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        return space.getAddress(offset);
    }

    private void loadMemory() {
        new Thread(() -> {
            try {
                String startText = startField.getText();
                String lenText = lengthField.getText();
                Memory mem = currentProgram.getMemory();
                String lower = lenText.trim().toLowerCase();
                StringBuilder allDump = new StringBuilder();
                blockStartOffsets.clear();
                blockLengths.clear();
                List<byte[]> allBlocks = new ArrayList<>();

                if (lower.equals("all") || lower.equals("-1") || lower.equals("0")) {
                    // load all memory blocks
                    MemoryBlock[] blocks = mem.getBlocks();
                    for (MemoryBlock block : blocks) {
                        long blen = block.getEnd().getOffset() - block.getStart().getOffset() + 1;
                        if (blen <= 0) continue;
                        if (blen > Integer.MAX_VALUE) throw new IllegalArgumentException("Block too large");
                        int ilen = (int) blen;
                        byte[] data = new byte[ilen];
                        mem.getBytes(block.getStart(), data);
                        allDump.append(bytesToHexDump(block.getStart(), data));
                        blockStartOffsets.add(block.getStart().getOffset());
                        blockLengths.add(ilen);
                        allBlocks.add(data);
                    }
                    // build combined original
                    int total = allBlocks.stream().mapToInt(b -> b.length).sum();
                    byte[] combined = new byte[total];
                    int pos = 0;
                    for (byte[] b : allBlocks) {
                        System.arraycopy(b, 0, combined, pos, b.length);
                        pos += b.length;
                    }
                    originalCombined = combined;
                } else {
                    Address start = parseHexAddress(startText);
                    int len = Integer.parseInt(lenText.trim());
                    byte[] data = new byte[len];
                    mem.getBytes(start, data);
                    allDump.append(bytesToHexDump(start, data));
                    blockStartOffsets.clear();
                    blockLengths.clear();
                    blockStartOffsets.add(start.getOffset());
                    blockLengths.add(len);
                    originalCombined = data;
                }

                SwingUtilities.invokeLater(() -> {
                    populateTableFromCombined();
                    autosizeColumns();
                    statusLabel.setText("Loaded bytes from program (blocks: " + blockStartOffsets.size() + ")");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> statusLabel.setText("Error loading memory: " + ex.getMessage()));
            }
        }).start();
    }

    private String bytesToHexDump(Address base, byte[] data) {
        StringBuilder sb = new StringBuilder();
        int perLine = 16;
        long baseOffset = base.getOffset();
        for (int i = 0; i < data.length; i += perLine) {
            long addr = baseOffset + i;
            sb.append(String.format("%08X: ", addr));
            int lineLen = Math.min(perLine, data.length - i);
            for (int j = 0; j < lineLen; j++) {
                sb.append(String.format("%02X ", data[i + j]));
            }
            // pad
            for (int j = lineLen; j < perLine; j++) sb.append("   ");
            sb.append("  ");
            // ASCII
            for (int j = 0; j < lineLen; j++) {
                int v = data[i + j] & 0xFF;
                if (v >= 32 && v < 127) sb.append((char) v);
                else sb.append('.');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private Address getAddressForLinearOffset(int linearOffset) {
        int accum = 0;
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        for (int bi = 0; bi < blockLengths.size(); bi++) {
            int bl = blockLengths.get(bi);
            if (linearOffset < accum + bl) {
                long blockStart = blockStartOffsets.get(bi);
                int blockOffset = linearOffset - accum;
                return space.getAddress(blockStart + blockOffset);
            }
            accum += bl;
        }
        // fallback to program image base
        return currentProgram.getImageBase();
    }

    private void populateTableFromCombined() {
        int total = originalCombined == null ? 0 : originalCombined.length;
        int effective = (total == 0) ? perLine : Math.min(perLine, Math.max(1, total));
        if (effective != modelPerLine) {
            modelPerLine = effective;
            rebuildTableModel(modelPerLine);
        }
        tableModel.setRowCount(0);
        int rows = (total + modelPerLine - 1) / modelPerLine;
        for (int r = 0; r < rows; r++) {
            int linearOffset = r * modelPerLine;
            Address a = getAddressForLinearOffset(linearOffset);
            String addr = String.format("%08X", a.getOffset());
            StringBuilder bytesSb = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int c = 0; c < modelPerLine; c++) {
                int idx = linearOffset + c;
                if (idx < total) {
                    int v = originalCombined[idx] & 0xFF;
                    if (bytesSb.length() > 0) bytesSb.append(' ');
                    bytesSb.append(String.format("%02X", v));
                    ascii.append((v >= 32 && v < 127) ? (char) v : '.');
                }
            }
            Object[] row = new Object[3];
            row[0] = addr;
            row[1] = bytesSb.toString();
            row[2] = ascii.toString();
            tableModel.addRow(row);
        }
    }

    private void rebuildTableModel(int newPerLine) {
        modelPerLine = newPerLine;
        // Build a 3-column model: Address | Bytes | ASCII
        String[] cols = new String[] { "Address", "Bytes", "ASCII" };
        tableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // viewer mode: no cells are editable
                return false;
            }
        };
        table.setModel(tableModel);
        // allow selecting individual cells so Bytes or ASCII cells can be selected/copy-pasted
        table.setCellSelectionEnabled(true);
        // permit selecting cells across rows/columns (but still use cell mode)
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(true);
        table.setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        // bind Ctrl-C to copy selected cells (supports multi-row selections)
        javax.swing.KeyStroke copyKey = javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK, false);
        table.getInputMap(JComponent.WHEN_FOCUSED).put(copyKey, "copy");
        table.getActionMap().put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                try {
                    int[] rows = table.getSelectedRows();
                    int[] cols = table.getSelectedColumns();
                    if (rows == null || cols == null || rows.length == 0 || cols.length == 0) {
                        int r = table.getSelectedRow();
                        int c = table.getSelectedColumn();
                        if (r >= 0 && c >= 0) {
                            Object v = table.getValueAt(r, c);
                            String s = v == null ? "" : v.toString();
                            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
                            if (statusLabel != null) statusLabel.setText("Copied cell");
                        }
                        return;
                    }

                    // sort rows and cols
                    java.util.Arrays.sort(rows);
                    java.util.Arrays.sort(cols);

                    StringBuilder sb = new StringBuilder();
                    // concatenate all selected cells inline in row-major order
                    // If the selection is a single column and it's the Bytes column (index 1),
                    // append a space after each row's bytes to keep rows separated inline.
                    boolean singleColBytes = (cols.length == 1 && cols[0] == 1);
                    for (int ri = 0; ri < rows.length; ri++) {
                        int r = rows[ri];
                        for (int ci = 0; ci < cols.length; ci++) {
                            int c = cols[ci];
                            Object v = table.getValueAt(r, c);
                            if (v != null) sb.append(v.toString());
                        }
                        if (singleColBytes) sb.append(' ');
                    }

                    StringSelection sel = new StringSelection(sb.toString());
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                    if (statusLabel != null) statusLabel.setText("Copied " + rows.length + " rows");
                } catch (Exception ex) {
                    // ignore copy errors
                }
            }
        });
        table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        DefaultTableCellRenderer addrR = new DefaultTableCellRenderer();
        addrR.setHorizontalAlignment(DefaultTableCellRenderer.LEFT);
        table.getColumnModel().getColumn(0).setCellRenderer(addrR);
        DefaultTableCellRenderer bytesR = new DefaultTableCellRenderer();
        bytesR.setHorizontalAlignment(DefaultTableCellRenderer.LEFT);
        bytesR.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        table.getColumnModel().getColumn(1).setCellRenderer(bytesR);
        DefaultTableCellRenderer asciiR = new DefaultTableCellRenderer();
        asciiR.setHorizontalAlignment(DefaultTableCellRenderer.LEFT);
        table.getColumnModel().getColumn(2).setCellRenderer(asciiR);

        // Bytes and ASCII are view-only; install renderer for bytes column
        BytesCellRenderer bytesRenderer = new BytesCellRenderer();
        table.getColumnModel().getColumn(1).setCellRenderer(bytesRenderer);

        // update ASCII column automatically when the Bytes cell changes
        tableModel.addTableModelListener(e -> {
            if (e.getType() != javax.swing.event.TableModelEvent.UPDATE) return;
            int col = e.getColumn();
            // only respond to updates to the Bytes column (1) or when all columns changed
            if (col != 1 && col != javax.swing.event.TableModelEvent.ALL_COLUMNS) return;
            int first = e.getFirstRow();
            int last = e.getLastRow();
            for (int r = Math.max(0, first); r <= Math.min(last, tableModel.getRowCount()-1); r++) {
                Object cell = tableModel.getValueAt(r, 1);
                String bytesText = cell == null ? "" : cell.toString();
                String ascii = bytesTextToAscii(bytesText);
                // updating ASCII (column 2) will not re-trigger this listener because
                // the listener only reacts to column 1 updates
                tableModel.setValueAt(ascii, r, 2);
            }
        });
    }

    // (Removed read-only cell editor — viewer mode uses renderers only)

    // (Removed editable Bytes cell editor — viewer mode uses renderer only)

    private static class BytesCellRenderer extends DefaultTableCellRenderer {
        BytesCellRenderer() {
            setHorizontalAlignment(DefaultTableCellRenderer.LEFT);
            setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        }

        @Override
        protected void setValue(Object value) {
            if (value == null) { super.setValue(""); return; }
            String s = value.toString().trim().toUpperCase();
            super.setValue(s);
        }
    }

    private byte[] parseTableToCombined() {
        int total = originalCombined == null ? 0 : originalCombined.length;
        byte[] out = new byte[total];
        for (int idx = 0; idx < total; idx++) {
            int r = idx / modelPerLine;
            int c = idx % modelPerLine;
            // read from Bytes column, which contains space-separated hex pairs for the row
            int row = r;
            Object bytesCell = tableModel.getValueAt(row, 1);
            String bytesText = bytesCell == null ? "" : bytesCell.toString();
            // extract hex pairs from the bytesText
            java.util.regex.Matcher m = HEX_PAIR_PATTERN.matcher(bytesText);
            int colIndex = 0;
            byte val = originalCombined[idx];
            while (m.find()) {
                if (colIndex == c) {
                    try {
                        val = (byte) Integer.parseInt(m.group(1), 16);
                    } catch (Exception ex) {
                        val = originalCombined[idx];
                    }
                    break;
                }
                colIndex++;
            }
            out[idx] = val;
        }
        return out;
    }

    private static String bytesTextToAscii(String bytesText) {
        StringBuilder sb = new StringBuilder();
            java.util.regex.Matcher m = HEX_PAIR_PATTERN.matcher(bytesText);
        while (m.find()) {
            try {
                int v = Integer.parseInt(m.group(1), 16) & 0xFF;
                sb.append((v >= 32 && v < 127) ? (char) v : '.');
            } catch (Exception e) {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private int lastSearchIndex = -1;

    private void doFind(boolean forward) {
        try {
            byte[] hay = parseTableToCombined();
            String query = searchField.getText();
            if (query == null || query.isEmpty()) return;
            final byte[] needle;
            String nq = query.trim();
            if (nq.matches("^[0-9A-Fa-f\\s]+$")) {
                // hex search
                nq = nq.replaceAll("\\s+", "");
                int len = nq.length() / 2;
                needle = new byte[len];
                for (int i = 0; i < len; i++) needle[i] = (byte) Integer.parseInt(nq.substring(i * 2, i * 2 + 2), 16);
            } else {
                needle = nq.getBytes(StandardCharsets.UTF_8);
            }

            int start = 0;
            if (lastSearchIndex >= 0) start = forward ? lastSearchIndex + 1 : lastSearchIndex - 1;
            int found = -1;
            if (forward) {
                for (int i = Math.max(0, start); i + needle.length <= hay.length; i++) {
                    boolean ok = true;
                    for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
                    if (ok) { found = i; break; }
                }
            } else {
                for (int i = Math.min(hay.length - needle.length, Math.max(0, start)); i >= 0; i--) {
                    boolean ok = true;
                    for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
                    if (ok) { found = i; break; }
                }
            }

            if (found >= 0) {
                lastSearchIndex = found;
                int row = found / modelPerLine;
                // select the Bytes cell for that row
                int viewCol = 1;
                table.changeSelection(row, viewCol, false, false);
                table.scrollRectToVisible(table.getCellRect(row, viewCol, true));
                statusLabel.setText("Found at offset 0x" + String.format("%X", found));
            } else {
                statusLabel.setText("Not found");
            }
        } catch (Exception e) {
            statusLabel.setText("Search error: " + e.getMessage());
        }
    }

    // old text parser removed; use table model parsing instead

    private void exportToFile() {
        try {
            byte[] data = parseTableToCombined();
            JFileChooser chooser = new JFileChooser();
            int ret = chooser.showSaveDialog(frame);
            if (ret == JFileChooser.APPROVE_OPTION) {
                Path p = chooser.getSelectedFile().toPath();
                Files.write(p, data);
                statusLabel.setText("Exported " + data.length + " bytes to " + p.toString());
            }
        } catch (Exception ex) {
            statusLabel.setText("Export error: " + ex.getMessage());
        }
    }

    private void importFromFile() {
        try {
            JFileChooser chooser = new JFileChooser();
            int ret = chooser.showOpenDialog(frame);
            if (ret == JFileChooser.APPROVE_OPTION) {
                Path p = chooser.getSelectedFile().toPath();
                byte[] data = Files.readAllBytes(p);
                // replace table data with imported bytes
                originalCombined = data;
                // recompute blocks to a single synthetic block starting at image base
                blockStartOffsets.clear();
                blockLengths.clear();
                blockStartOffsets.add(currentProgram.getImageBase().getOffset());
                blockLengths.add(data.length);
                populateTableFromCombined();
                autosizeColumns();
                statusLabel.setText("Imported " + data.length + " bytes from " + p.toString());
            }
        } catch (Exception ex) {
            statusLabel.setText("Import error: " + ex.getMessage());
        }
    }

    private void autosizeColumns() {
        // Turn off auto-resize to allow setting preferred widths
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        for (int col = 0; col < table.getColumnCount(); col++) {
            int maxWidth = 50; // minimum
            TableColumn tc = table.getColumnModel().getColumn(col);
            TableCellRenderer headerRenderer = tc.getHeaderRenderer();
            if (headerRenderer == null) headerRenderer = table.getTableHeader().getDefaultRenderer();
            Component headerComp = headerRenderer.getTableCellRendererComponent(table, tc.getHeaderValue(), false, false, 0, col);
            maxWidth = Math.max(maxWidth, headerComp.getPreferredSize().width + 10);
            int rows = table.getRowCount();
            for (int r = 0; r < rows; r++) {
                TableCellRenderer renderer = table.getCellRenderer(r, col);
                Object value = table.getValueAt(r, col);
                Component comp = renderer.getTableCellRendererComponent(table, value, false, false, r, col);
                if (comp != null) maxWidth = Math.max(maxWidth, comp.getPreferredSize().width + 10);
            }
            tc.setPreferredWidth(maxWidth);
        }
        table.revalidate();
        table.repaint();
    }

}
