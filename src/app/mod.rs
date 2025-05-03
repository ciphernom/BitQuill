pub mod input;
pub mod ui;

use crate::constants::*;
use crate::error::{BitQuillError, BitQuillResult};
use crate::merkle::{MerkleDocument, VerificationLevel};

use crate::utils;

use crossterm::event::KeyCode;

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

// Dialog for file operations
#[derive(PartialEq, Clone)] 
pub enum Dialog {
    None,
    SaveAs,
    Open,
    NewConfirm,
    Metadata,
    Export,
    UnsavedChanges(UnsavedAction),
}

// What action triggered unsaved changes dialog
#[derive(PartialEq, Clone)]
pub enum UnsavedAction {
    New,
    Open,
    Quit,
    OpenRecent(usize),
}

// File Browser component
pub struct FileBrowser {
    pub current_dir: PathBuf,
    pub entries: Vec<PathBuf>,
    pub selected_idx: usize,
    pub filter: Option<String>, // e.g., "bq", "bqc"
    pub filename_input: String,
    pub is_editing_filename: bool,
}

// TUI App state
#[derive(PartialEq)]
pub enum AppMode {
    Editing,
    Viewing,        // View leaf history
    VerifyDetail,   // View verification results
    TreeView,       // View Merkle tree structure
    FileDialog,     // Indicates a file dialog is active
    MetadataEdit,   // Editing metadata fields
    Help,           // Display help screen
    Search,         // Mode for search/replace
}

// Multi-line text buffer for the editor
pub struct TextBuffer {
    pub lines: Vec<String>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub last_edit_time: Instant,
    pub edit_idle_threshold: Duration,
    pub content_history: VecDeque<String>,
    pub max_history: usize,
    pub scroll_offset: usize, // For scrolling in long documents
    pub line_numbers: bool,   // Display line numbers
    pub max_line_length: usize, // Maximum line length (to prevent memory issues)
}

// Search/Replace state
pub struct SearchState {
    pub search_query: String,
    pub replace_text: String,
    pub case_sensitive: bool,
    pub current_matches: Vec<(usize, usize, usize)>, // (row, start_col, end_col)
    pub current_match_idx: Option<usize>,
    pub is_replace_mode: bool,
    pub is_active: bool,
}

// Metadata editor dialog state
pub struct MetadataEditor {
    pub metadata: crate::merkle::DocumentMetadata,
    pub current_field: usize, // 0: title, 1: author, 2: keywords, 3: description
    pub editing: bool,
    pub edit_buffer: String,
    pub max_field_length: usize, // Maximum field length
}

pub struct App {
    pub document: MerkleDocument,
    pub buffer: TextBuffer,
    pub history_scroll: usize, // Scroll offset for lists
    pub mode: AppMode,
    pub message: String,
    pub last_auto_save: Instant,
    pub file_path: Option<PathBuf>,
    pub recent_files: Vec<PathBuf>,
    pub dialog: Dialog,
    pub file_browser: FileBrowser,
    pub metadata_editor: Option<MetadataEditor>,
    pub should_quit: bool,
    pub status_time: Instant, // For temporary status indicators
    pub show_tick_indicator: bool,
    pub auto_save_enabled: bool,
    pub search_state: SearchState,
}

impl FileBrowser {
    pub fn new() -> BitQuillResult<Self> {
        let current_dir = match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                // Fallback to home directory or working directory
                let fallback = match dirs::home_dir() {
                    Some(home) => home,
                    None => PathBuf::from(".")
                };
                
                eprintln!("Warning: Failed to get current dir: {}, using fallback", e);
                fallback
            }
        };
        
        // Scan initially without filter
        let entries = match Self::scan_directory(&current_dir, None) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("Warning: Failed to scan directory: {}", e);
                Vec::new()
            }
        };

        Ok(FileBrowser {
            current_dir,
            entries,
            selected_idx: 0,
            filter: None,
            filename_input: String::new(),
            is_editing_filename: false,
        })
    }

    // Scans directory, optionally filtering files by extension
    pub fn scan_directory(dir: &Path, filter_ext: Option<&str>) -> BitQuillResult<Vec<PathBuf>> {
        let mut entries = Vec::new();

        // Add parent directory ("..") option, unless already at root
        if let Some(parent) = dir.parent() {
            if parent != dir { // Basic check to avoid adding ".." at root
                entries.push(dir.join(".."));
            }
        }

        // Read directory entries
        match fs::read_dir(dir) {
            Ok(read_dir) => {
                let mut dirs = Vec::new();
                let mut files = Vec::new();

                for entry_result in read_dir {
                    match entry_result {
                        Ok(entry) => {
                            let path = entry.path();

                            // Basic hidden file check (Unix/macOS style)
                            if path.file_name()
                                .and_then(|n| n.to_str())
                                .map_or(false, |s| s.starts_with('.')) 
                            {
                                continue;
                            }

                            if path.is_dir() {
                                dirs.push(path);
                            } else if path.is_file() {
                                // Apply filter if specified
                                if let Some(ext_filter) = filter_ext {
                                    if path.extension().and_then(|e| e.to_str()) == Some(ext_filter) {
                                        files.push(path);
                                    }
                                } else {
                                    // No filter, include all files
                                    files.push(path);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Warning: Error reading directory entry: {}", e);
                            // Continue with next entry
                        }
                    }
                }

                // Sort directories and files alphabetically
                dirs.sort_by_key(|d| d.file_name().unwrap_or_default().to_ascii_lowercase());
                files.sort_by_key(|f| f.file_name().unwrap_or_default().to_ascii_lowercase());

                // Combine: ".." first, then sorted dirs, then sorted files
                entries.append(&mut dirs);
                entries.append(&mut files);
            },
            Err(e) => {
                return Err(BitQuillError::IoError(e));
            }
        }

        Ok(entries)
    }

    pub fn navigate_up(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    pub fn navigate_down(&mut self) {
        if !self.entries.is_empty() && self.selected_idx < self.entries.len() - 1 {
            self.selected_idx += 1;
        }
    }

    // Tries to enter the selected directory. Returns Ok(true) if successful, Ok(false) if not directory.
    pub fn enter_directory(&mut self) -> BitQuillResult<bool> {
        if self.entries.is_empty() || self.selected_idx >= self.entries.len() {
            return Ok(false); // Avoid panic on empty or out-of-bounds index
        }

        let selected_path = &self.entries[self.selected_idx];

        // Check if it's the ".." entry
        if selected_path.file_name().map_or(false, |name| name == "..") {
            if let Some(parent) = self.current_dir.parent() {
                self.current_dir = parent.to_path_buf();
                // Rescan with current filter
                self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref())?;
                self.selected_idx = 0; // Reset selection
                self.filename_input.clear(); // Clear filename input when changing dir
                self.is_editing_filename = false;
                return Ok(true);
            }
        } else if selected_path.is_dir() {
            // Canonicalize to handle symlinks etc. but fallback gracefully
            match fs::canonicalize(selected_path) {
                Ok(canonical_path) => {
                    self.current_dir = canonical_path;
                },
                Err(_) => {
                    self.current_dir = selected_path.to_path_buf();
                }
            }
            
            // Rescan with current filter
            self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref())?;
            self.selected_idx = 0; // Reset selection
            self.filename_input.clear(); // Clear filename input
            self.is_editing_filename = false;
            return Ok(true);
        }

        Ok(false) // Not a directory or ".."
    }

    // Gets the currently selected path (could be a file or directory)
    pub fn get_selected_path(&self) -> Option<PathBuf> {
        if self.entries.is_empty() || self.selected_idx >= self.entries.len() {
            None
        } else {
            Some(self.entries[self.selected_idx].clone())
        }
    }

    // Sets the file extension filter (e.g., "bq") and rescans
    pub fn set_filter(&mut self, ext: &str) -> BitQuillResult<()> {
        self.filter = Some(ext.to_string());
        self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref())?;
        self.selected_idx = 0; // Reset selection
        self.filename_input.clear();
        self.is_editing_filename = false;
        Ok(())
    }

    // Clears the file extension filter and rescans
    pub fn clear_filter(&mut self) -> BitQuillResult<()> {
        self.filter = None;
        self.entries = Self::scan_directory(&self.current_dir, None)?;
        self.selected_idx = 0; // Reset selection
        self.filename_input.clear();
        self.is_editing_filename = false;
        Ok(())
    }

    // Gets formatted entry names for display in the TUI List
    pub fn get_entries_for_display(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|path| {
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("[invalid path]");

                if name == ".." {
                    "⬆️  ../".to_string() // Use ".." consistently
                } else if path.is_dir() {
                    format!("📁 {}/", name)
                } else {
                    format!("📄 {}", name)
                }
            })
            .collect()
    }
    
    // Safely add a character to filename input (with length validation)
    pub fn add_to_filename(&mut self, c: char) -> bool {
        if self.filename_input.len() < 255 {  // Max filename length
            self.filename_input.push(c);
            true
        } else {
            false
        }
    }
}

impl SearchState {
    pub fn new() -> Self {
        SearchState {
            search_query: String::new(),
            replace_text: String::new(),
            case_sensitive: false,
            current_matches: Vec::new(),
            current_match_idx: None,
            is_replace_mode: false,
            is_active: false,
        }
    }
    
    pub fn reset(&mut self) {
        self.current_matches.clear();
        self.current_match_idx = None;
    }
    
    pub fn safely_add_to_query(&mut self, c: char) -> bool {
        if self.search_query.len() < 1000 {  // Prevent unbounded growth
            self.search_query.push(c);
            true
        } else {
            false
        }
    }
    
    pub fn safely_add_to_replace(&mut self, c: char) -> bool {
        if self.replace_text.len() < 1000 {  // Prevent unbounded growth
            self.replace_text.push(c);
            true
        } else {
            false
        }
    }
}

impl MetadataEditor {
    pub fn new(metadata: crate::merkle::DocumentMetadata) -> Self {
        MetadataEditor {
            metadata,
            current_field: 0,
            editing: false,
            edit_buffer: String::new(),
            max_field_length: 1000, // Reasonable max field length
        }
    }

    pub fn navigate_up(&mut self) {
        if self.editing { return; } // Don't navigate fields while editing buffer
        if self.current_field > 0 {
            self.current_field -= 1;
        }
    }

    pub fn navigate_down(&mut self) {
        if self.editing { return; } // Don't navigate fields while editing buffer
        // Adjust max field index if needed
        if self.current_field < 3 { // 0=title, 1=author, 2=keywords, 3=description
            self.current_field += 1;
        }
    }

    pub fn start_editing(&mut self) {
        if self.editing { return; } // Already editing
        self.editing = true;
        self.edit_buffer = match self.current_field {
            0 => self.metadata.title.clone(),
            1 => self.metadata.author.clone(),
            2 => self.metadata.keywords.join(", "), // Edit as comma-separated
            3 => self.metadata.description.clone(),
            _ => {
                self.editing = false; // Invalid field
                String::new()
            }
        };
    }

    pub fn handle_edit_key(&mut self, code: KeyCode) -> bool {
        if !self.editing { return false; }
        
        match code {
            KeyCode::Enter => {
                self.finish_editing();
                true
            },
            KeyCode::Esc => {
                self.cancel_editing();
                true
            },
            KeyCode::Backspace => { 
                self.edit_buffer.pop();
                true
            },
            KeyCode::Char(c) => {
                // Check length limit
                if self.edit_buffer.len() < self.max_field_length {
                    self.edit_buffer.push(c);
                }
                true
            },
            _ => false // Ignore other keys while editing buffer
        }
    }

    pub fn finish_editing(&mut self) {
        if !self.editing { return; }
        
        match self.current_field {
            0 => self.metadata.title = self.edit_buffer.trim().to_string(),
            1 => self.metadata.author = self.edit_buffer.trim().to_string(),
            2 => {
                self.metadata.keywords = self.edit_buffer
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()) // Remove empty keywords
                    .collect();
            },
            3 => self.metadata.description = self.edit_buffer.trim().to_string(),
            _ => {}
        }
        
        self.editing = false;
        self.edit_buffer.clear();
    }

    pub fn cancel_editing(&mut self) {
        if !self.editing { return; }
        self.editing = false;
        self.edit_buffer.clear();
    }

    pub fn get_metadata(&self) -> crate::merkle::DocumentMetadata {
        // Return a clone of the potentially modified metadata
        self.metadata.clone()
    }
}

impl TextBuffer {
    pub fn new(idle_threshold_ms: u64) -> Self {
        TextBuffer {
            lines: vec![String::new()],
            cursor_row: 0,
            cursor_col: 0,
            last_edit_time: Instant::now(),
            edit_idle_threshold: Duration::from_millis(idle_threshold_ms),
            content_history: VecDeque::new(),
            max_history: 50, // Increased history size
            scroll_offset: 0,
            line_numbers: true, // Enable line numbers by default
            max_line_length: 10000, // 10K chars per line
        }
    }
    
    // Find all matches of a query in the buffer
    pub fn find_all(&self, query: &str, case_sensitive: bool) -> Vec<(usize, usize, usize)> {
        if query.is_empty() {
            return Vec::new();
        }
        
        let mut matches = Vec::new();
        
        for (row_idx, line) in self.lines.iter().enumerate() {
            let haystack = if case_sensitive {
                line.clone()
            } else {
                line.to_lowercase()
            };
            
            let needle = if case_sensitive {
                query.to_string()
            } else {
                query.to_lowercase()
            };
            
            let mut start_idx = 0;
            while let Some(found_idx) = haystack[start_idx..].find(&needle) {
                let match_start = start_idx + found_idx;
                let match_end = match_start + needle.len();
                
                matches.push((row_idx, match_start, match_end));
                
                // Move past this match to find the next
                start_idx = match_start + 1;
                
                // Prevent unbounded loop for pathological cases 
                if matches.len() > 1000 {
                    break;
                }
            }
        }
        
        matches
    }
    
    // Move cursor to a specific match
    pub fn move_to_match(&mut self, matched_pos: (usize, usize, usize)) {
        let (row, col_start, _) = matched_pos;
        
        // Validate row within bounds
        if row >= self.lines.len() {
            return;
        }
        
        self.cursor_row = row;
        self.cursor_col = col_start;
        
        self.ensure_cursor_visible();
    }
    
    // Replace a specific match with new text
    pub fn replace_match(&mut self, matched_pos: (usize, usize, usize), replace_with: &str) -> bool {
        let (row, col_start, col_end) = matched_pos;
        
        // Make sure the positions are valid
        if row >= self.lines.len() {
            return false;
        }
        
        let line = &mut self.lines[row];
        
        if col_start > col_end || col_end > line.len() {
            return false;
        }
        
        // Check that replacement won't exceed max line length
        if line.len() - (col_end - col_start) + replace_with.len() > self.max_line_length {
            return false;
        }
        
        // Remove the matched text
        let before = line[0..col_start].to_string();
        let after = line[col_end..].to_string();
        
        // Replace with the new text
        *line = format!("{}{}{}", before, replace_with, after);
        
        // Update cursor position to the end of the inserted text
        self.cursor_row = row;
        self.cursor_col = col_start + replace_with.len();
        
        self.last_edit_time = Instant::now();
        self.ensure_cursor_visible();
        
        true
    }
    
    // Replace all matches in the buffer
    pub fn replace_all(&mut self, matches: &[(usize, usize, usize)], replace_with: &str) -> usize {
        let mut replaced_count = 0;
        
        // Process matches from bottom to top to avoid invalidating positions
        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by(|a, b| {
            let (a_row, a_col, _) = a;
            let (b_row, b_col, _) = b;
            
            b_row.cmp(a_row).then(b_col.cmp(a_col))
        });
        
        for &matched_pos in &sorted_matches {
            if self.replace_match(matched_pos, replace_with) {
                replaced_count += 1;
            }
        }
        
        if replaced_count > 0 {
            self.last_edit_time = Instant::now();
            // Record history after batch replace
            self.record_history();
        }
        
        replaced_count
    }

    pub fn insert_char(&mut self, c: char) -> bool {
        if c == '\n' {
            // Split the current line at cursor
            if self.cursor_row >= self.lines.len() {
                // Bounds check
                return false;
            }
            
            let current_line = &self.lines[self.cursor_row];
            
            // Check that cursor_col is valid
            if self.cursor_col > current_line.len() {
                self.cursor_col = current_line.len();
            }
            
            let new_line = current_line[self.cursor_col..].to_string();
            self.lines[self.cursor_row] = current_line[..self.cursor_col].to_string();

            // Insert new line
            if self.lines.len() >= MAX_BUFFER_SIZE {
                return false; // Too many lines
            }
            self.lines.insert(self.cursor_row + 1, new_line);

            // Move cursor to start of new line
            self.cursor_row += 1;
            self.cursor_col = 0;
        } else {
            // Insert character at cursor position
            if self.cursor_row >= self.lines.len() {
                // Bounds check
                return false;
            }
            
            // Ensure cursor_col is valid for insertion (can be == len)
            let current_line_len = self.lines[self.cursor_row].len();
            if self.cursor_col > current_line_len {
                self.cursor_col = current_line_len;
            }
            
            // Check line length limit
            if self.lines[self.cursor_row].len() >= self.max_line_length {
                return false; // Line too long
            }
            
            // Actually insert character
            self.lines[self.cursor_row].insert(self.cursor_col, c);
            self.cursor_col += 1;
        }

        self.last_edit_time = Instant::now();
        // Don't record every char insert for undo, wait for idle
        self.ensure_cursor_visible();
        true
    }

    pub fn delete_char(&mut self) -> bool {
        if self.cursor_col > 0 {
            // Delete character before cursor
            if self.cursor_row >= self.lines.len() {
                return false; // Bounds check
            }
            
            if self.cursor_col > self.lines[self.cursor_row].len() {
                self.cursor_col = self.lines[self.cursor_row].len();
            }
            
            if self.cursor_col > 0 {
                self.lines[self.cursor_row].remove(self.cursor_col - 1);
                self.cursor_col -= 1;
            }
        } else if self.cursor_row > 0 {
            // At start of line, merge with previous line
            if self.cursor_row >= self.lines.len() {
                return false; // Bounds check
            }
            
            let current_line = self.lines.remove(self.cursor_row);
            let prev_line_len = self.lines[self.cursor_row - 1].len();
            
            // Check if merged line would be too long
            if prev_line_len + current_line.len() > self.max_line_length {
                // Revert the removal and don't merge
                self.lines.insert(self.cursor_row, current_line);
                return false;
            }
            
            self.lines[self.cursor_row - 1].push_str(&current_line);

            // Move cursor to end of previous line
            self.cursor_row -= 1;
            self.cursor_col = prev_line_len;
        } else {
            // At start of document, nothing to delete
            return false;
        }

        self.last_edit_time = Instant::now();
        self.ensure_cursor_visible();
        true
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            // Move to end of previous line
            self.cursor_row -= 1;
            if self.cursor_row < self.lines.len() { // Bounds check
                self.cursor_col = self.lines[self.cursor_row].len();
            } else {
                self.cursor_col = 0;
            }
        }
        self.ensure_cursor_visible();
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor_row >= self.lines.len() {
            // Out of bounds, reset to last line
            self.cursor_row = self.lines.len().saturating_sub(1);
            self.cursor_col = 0;
            self.ensure_cursor_visible();
            return;
        }
        
        let current_line_len = self.lines[self.cursor_row].len();
        if self.cursor_col < current_line_len {
            self.cursor_col += 1;
        } else if self.cursor_row < self.lines.len() - 1 {
            // Move to start of next line
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
        self.ensure_cursor_visible();
    }

    pub fn move_cursor_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            // Adjust column if new line is shorter
            if self.cursor_row < self.lines.len() { // Bounds check
                self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
            }
        }
        self.ensure_cursor_visible();
    }

    pub fn move_cursor_down(&mut self) {
        if self.cursor_row < self.lines.len() - 1 {
            self.cursor_row += 1;
            // Adjust column if new line is shorter
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        self.ensure_cursor_visible();
    }

    pub fn move_cursor_home(&mut self) {
        self.cursor_col = 0;
    }

    pub fn move_cursor_end(&mut self) {
        if self.cursor_row < self.lines.len() { // Bounds check
            self.cursor_col = self.lines[self.cursor_row].len();
        }
    }

    pub fn page_up(&mut self, height: usize) {
        let effective_height = height.saturating_sub(1); // Move by almost a full page
        let target_row = self.cursor_row.saturating_sub(effective_height);
        self.cursor_row = target_row;
        if self.cursor_row < self.lines.len() { // Bounds check
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        self.ensure_cursor_visible();
    }

    pub fn page_down(&mut self, height: usize) {
        let effective_height = height.saturating_sub(1); // Move by almost a full page
        let target_row = self.cursor_row.saturating_add(effective_height);
        self.cursor_row = target_row.min(self.lines.len().saturating_sub(1)); // Ensure bounds
        if self.cursor_row < self.lines.len() { // Bounds check
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        self.ensure_cursor_visible();
    }

    pub fn ensure_cursor_visible(&mut self) {
        // Check if cursor is in a valid position
        self.cursor_row = self.cursor_row.min(self.lines.len().saturating_sub(1));
        if self.cursor_row < self.lines.len() {
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        
        // Determine visible height (needs adjustment based on actual rendering context)
        // This is tricky without knowing the exact layout height. Assume 20 for now.
        let visible_height = 20; // Placeholder height

        // Adjust scroll offset if cursor moved above the visible area
        if self.cursor_row < self.scroll_offset {
            self.scroll_offset = self.cursor_row;
        }
        // Adjust scroll offset if cursor moved below the visible area
        else if self.cursor_row >= self.scroll_offset + visible_height {
            self.scroll_offset = self.cursor_row - visible_height + 1;
        }
    }

    pub fn get_content(&self) -> String {
        self.lines.join("\n")
    }

    // Get lines for display within a given height, handling scroll offset
    pub fn get_display_lines(&self, height: usize) -> Vec<String> {
        // Validate scroll offset to prevent out-of-bounds access
        let valid_scroll_offset = self.scroll_offset.min(self.lines.len().saturating_sub(1));
        
        // Calculate maximum line number width needed for the *entire document*
        let line_num_width = if self.line_numbers {
            self.lines.len().to_string().len()
        } else {
            0
        };

        self.lines
            .iter()
            .enumerate()
            .skip(valid_scroll_offset) // Start from the scroll offset
            .take(height)            // Take only enough lines to fill the height
            .map(|(i, line)| {
                if self.line_numbers {
                    // Format with padding based on max width
                    format!("{:<width$} │ {}", i + 1, line, width = line_num_width)
                } else {
                    line.clone()
                }
            })
            .collect()
    }

    pub fn is_idle(&self) -> bool {
        self.last_edit_time.elapsed() >= self.edit_idle_threshold
    }

    // Record current content state to undo history
    pub fn record_history(&mut self) {
        let content = self.get_content();

        // Don't record if content is unchanged from last history state
        if let Some(last) = self.content_history.back() {
            if *last == content {
                return;
            }
        } else if content.is_empty() && self.lines.len() == 1 {
            // Don't record initial empty state if history is empty
            return;
        }

        // Add to history
        self.content_history.push_back(content);

        // Trim history if needed
        while self.content_history.len() > self.max_history {
            self.content_history.pop_front();
        }
    }

    // Check if content differs from the last recorded history state
    pub fn has_changes_since_last_record(&self) -> bool {
        if let Some(last) = self.content_history.back() {
            self.get_content() != *last
        } else {
            // If history is empty, any content is considered a change
            !self.get_content().is_empty() || self.lines.len() > 1
        }
    }

    pub fn load_content(&mut self, content: &str) -> bool {
        // Check size limits
        if content.len() > MAX_BUFFER_SIZE {
            return false;
        }
        
        // Clear current buffer
        self.lines.clear();
        self.cursor_row = 0;
        self.cursor_col = 0;
        self.scroll_offset = 0;
        self.content_history.clear(); // Clear history on load

        // Load content line by line with validation
        let mut new_lines: Vec<String> = Vec::new();
        for line in content.lines() {
            if line.len() > self.max_line_length {
                // Line too long, truncate
                let truncated = line.chars().take(self.max_line_length).collect();
                new_lines.push(truncated);
            } else {
                new_lines.push(line.to_string());
            }
            
            // Check total line limit
            if new_lines.len() >= MAX_BUFFER_SIZE / 100 {  // Arbitrary limit - 1% of max buffer size
                break;
            }
        }
        
        if new_lines.is_empty() {
            self.lines.push(String::new()); // Ensure at least one empty line
        } else {
            self.lines = new_lines;
        }

        // Record the loaded state as the initial history point
        self.record_history();
        self.last_edit_time = Instant::now(); // Reset edit time
        
        true
    }

    pub fn toggle_line_numbers(&mut self) {
        self.line_numbers = !self.line_numbers;
    }

    // Get cursor position (1-based) for UI display
    pub fn get_cursor_position(&self) -> (usize, usize) {
        (self.cursor_row + 1, self.cursor_col + 1)
    }

    // Undo functionality
    pub fn undo(&mut self) -> bool {
        if self.content_history.len() > 1 {
            // Remove current state (the one most recently added)
            self.content_history.pop_back();

            // Get the previous state from the history
            if let Some(previous_content) = self.content_history.back().cloned() {
                // Load the previous content without adding it back to history
                let current_cursor_row = self.cursor_row; // Store cursor roughly
                let current_cursor_col = self.cursor_col;

                // Split into lines
                let prev_lines: Vec<String> = previous_content.lines().map(|l| l.to_string()).collect();
                
                // Load previous content
                self.lines = if prev_lines.is_empty() {
                    vec![String::new()]
                } else {
                    prev_lines
                };

                // Try to restore cursor position (might be imperfect)
                self.cursor_row = current_cursor_row.min(self.lines.len().saturating_sub(1));
                if self.cursor_row < self.lines.len() {
                    self.cursor_col = current_cursor_col.min(self.lines[self.cursor_row].len());
                } else {
                    self.cursor_col = 0;
                }

                self.last_edit_time = Instant::now(); // Mark as edited
                self.ensure_cursor_visible();
                
                return true;
            }
        } else if self.content_history.len() == 1 {
            // If only one state left (initial loaded/new state), clear the buffer
            self.lines = vec![String::new()];
            self.cursor_row = 0;
            self.cursor_col = 0;
            self.scroll_offset = 0;
            self.content_history.pop_back(); // Remove the last state
            self.last_edit_time = Instant::now();
            
            return true;
        }
        
        false
    }
}

impl App {
    pub fn new() -> BitQuillResult<Self> {
        // Load recent files if available
        let recent_files = match Self::load_recent_files() {
            Ok(files) => files,
            Err(e) => {
                eprintln!("Warning: Failed to load recent files: {}", e);
                Vec::new()
            }
        };
        
        // Create file browser with error handling
        let file_browser = match FileBrowser::new() {
            Ok(browser) => browser,
            Err(e) => {
                eprintln!("Warning: Failed to initialize file browser: {}", e);
                return Err(e);
            }
        };
        
        // Create MerkleDocument with error handling
        let document = match MerkleDocument::new() {
            Ok(doc) => doc,
            Err(e) => {
                eprintln!("Error: Failed to initialize document: {}", e);
                return Err(e);
            }
        };

        Ok(App {
            document,
            buffer: TextBuffer::new(2000),  // 2 second idle threshold for history commit
            history_scroll: 0,
            mode: AppMode::Editing,
            message: String::from("Welcome to BitQuill - Merkle Edition! Press F1 for help."),
            last_auto_save: Instant::now(),
            file_path: None,
            recent_files,
            dialog: Dialog::None,
            file_browser,
            metadata_editor: None,
            should_quit: false,
            status_time: Instant::now(),
            show_tick_indicator: false,
            auto_save_enabled: true, // Auto-save on by default
            search_state: SearchState::new(),
        })
    }

    // Simplified char insertion - delegates to buffer
    pub fn insert_char(&mut self, c: char) -> bool {
        if self.buffer.insert_char(c) {
            // Mark document as dirty immediately on change
            self.document.dirty = true;
            true
        } else {
            false
        }
    }

    // Simplified char deletion - delegates to buffer
    pub fn delete_char(&mut self) -> bool {
        if self.buffer.delete_char() {
            // Mark document as dirty immediately on change
            self.document.dirty = true;
            true
        } else {
            false
        }
    }

    // Toggle between primary modes (Edit/View)
    pub fn toggle_edit_view_mode(&mut self) {
        match self.mode {
            AppMode::Editing => {
                // Before switching away from editing, record pending changes if any
                if self.buffer.has_changes_since_last_record() {
                    match self.document.record_change(self.buffer.get_content()) {
                        Ok(_) => {
                            self.buffer.record_history(); // Commit to buffer history too
                            self.message = "Changes recorded, switching to View mode.".to_string();
                        },
                        Err(e) => {
                            self.message = format!("Error recording changes: {}", e);
                            return; // Don't switch modes if error
                        }
                    }
                } else {
                    self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                }
                self.mode = AppMode::Viewing;
                self.history_scroll = 0; // Reset scroll when entering view mode
            },
            AppMode::Viewing => {
                self.mode = AppMode::Editing;
                self.message = "Editing mode".to_string();
            },
            AppMode::VerifyDetail => {
                self.mode = AppMode::Viewing;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                self.history_scroll = 0;
            },
            AppMode::TreeView => {
                self.mode = AppMode::Viewing;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                self.history_scroll = 0;
            },
            _ => {
                // Don't toggle if in other modes like Help, FileDialog, MetadataEdit
            }
        }
    }

    // Toggle tree view mode (show Merkle tree structure)
    pub fn toggle_tree_view(&mut self) {
        match self.mode {
            AppMode::Viewing | AppMode::VerifyDetail => {
                self.mode = AppMode::TreeView;
                self.history_scroll = 0;
                self.message = "Tree View - Showing Merkle tree structure".to_string();
            },
            AppMode::TreeView => {
                self.mode = AppMode::Viewing;
                self.history_scroll = 0;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
            },
            _ => {
                // Only toggle from View/Verify modes
            }
        }
    }

    pub fn toggle_help(&mut self) {
        if self.mode == AppMode::Help {
            // Exit help mode, return to Editing (or previous mode?) - let's default to Editing
            self.mode = AppMode::Editing;
            self.message = "Help closed.".to_string();
        } else {
            // Enter help mode
            // Record pending changes before leaving editing state
            if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
                match self.document.record_change(self.buffer.get_content()) {
                    Ok(_) => self.buffer.record_history(),
                    Err(e) => {
                        self.message = format!("Error recording changes: {}", e);
                        return; // Don't switch modes if error
                    }
                }
            }
            self.mode = AppMode::Help;
            self.message = "Showing help. Press F1 or Esc to close.".to_string();
        }
    }

    pub fn update(&mut self) -> BitQuillResult<()> {
        // Process any new VDF clock ticks and potentially create leaves
        let tick_before = self.document.latest_tick.as_ref().map(|t| t.sequence_number);
        let leaf_created = self.document.process_vdf_ticks()?;
        let tick_after = self.document.latest_tick.as_ref().map(|t| t.sequence_number);

        if leaf_created {
            self.message = format!("New leaf #{} created (VDF tick #{})",
                                  self.document.leaves.len(),
                                  tick_after.unwrap_or(0));
            self.show_tick_indicator = true; // Indicate leaf creation visually
            self.status_time = Instant::now();
        } else if tick_after != tick_before && tick_after.is_some() {
            // Show tick indicator even if no leaf was created this cycle
            self.message = format!("VDF Tick #{} received (diff: {})", 
                                  tick_after.unwrap_or(0),
                                  self.document.current_iterations);
            self.show_tick_indicator = true;
            self.status_time = Instant::now();
        }

        // Check for idle edits in Editing mode and commit to history/document state
        if self.mode == AppMode::Editing && self.buffer.is_idle() && self.buffer.has_changes_since_last_record() {
            let content = self.buffer.get_content();
            match self.document.record_change(content) {
                Ok(_) => {
                    self.buffer.record_history(); // Record in undo history
                    self.message = "Changes recorded - waiting for next Merkle leaf creation".to_string();
                    // Mark dirty flag here too, although record_change should do it.
                    self.document.dirty = true;
                },
                Err(e) => {
                    self.message = format!("Error recording changes: {}", e);
                }
            }
        }

        // Auto-save if enabled, document is dirty, path exists, and interval passed
        if self.auto_save_enabled &&
           self.document.has_unsaved_changes() && // Use dirty flag
           self.file_path.is_some() &&
           Instant::now().duration_since(self.last_auto_save) > Duration::from_secs(AUTO_SAVE_INTERVAL) {

            // Before saving, ensure latest buffer changes are recorded if in editing mode
            if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
                match self.document.record_change(self.buffer.get_content()) {
                    Ok(_) => self.buffer.record_history(),
                    Err(e) => {
                        self.message = format!("Error recording changes: {}", e);
                    }
                }
            }

            // Now attempt to save
            if let Err(e) = self.save_document() {
                self.message = format!("Auto-save error: {}", e);
            } else {
                self.message = format!("Document auto-saved to {}", self.file_path.as_ref().unwrap().display());
            }
            self.last_auto_save = Instant::now();
        }

        // Clear temporary status indicators after a few seconds
        if self.show_tick_indicator && Instant::now().duration_since(self.status_time) > Duration::from_secs(3) {
            self.show_tick_indicator = false;
            // Maybe clear the message related to the indicator? Or let the next message overwrite.
        }
        
        Ok(())
    }

    // Save document to current file_path or trigger SaveAs dialog
    pub fn save_document(&mut self) -> BitQuillResult<()> {
        // Ensure latest buffer changes are recorded before saving
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }

        match &self.file_path {
            Some(p) => {
                let path_clone = p.clone(); // Clone to satisfy borrow checker
                self.document.save_to_file(&path_clone)?; // This now sets dirty = false
                self.add_to_recent_files(&path_clone)?; // Update recent files
                self.message = format!("Document saved to {}", path_clone.display());
                self.last_auto_save = Instant::now(); // Reset auto-save timer on manual save
                Ok(())
            },
            None => {
                // No path set - trigger SaveAs dialog
                self.trigger_save_as_dialog()?;
                // Indicate failure for now, dialog will handle the save later
                Err(BitQuillError::StateError("Save As dialog triggered".to_string()))
            }
        }
    }

    // Trigger SaveAs dialog state change
    pub fn trigger_save_as_dialog(&mut self) -> BitQuillResult<()> {
        self.mode = AppMode::FileDialog; // Switch mode
        self.dialog = Dialog::SaveAs; // Set specific dialog type
        self.file_browser.set_filter(BITQUILL_FILE_EXT)?; // Set filter for .bq files
        self.file_browser.filename_input = self.file_path // Pre-fill filename if available
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Untitled.bq".to_string());
        self.file_browser.is_editing_filename = true; // Start editing the filename
        self.message = "Save As: Enter filename and press Enter.".to_string();
        Ok(())
    }

    // Confirm SaveAs action from dialog input
    pub fn confirm_save_as(&mut self) -> BitQuillResult<()> {
        let filename = self.file_browser.filename_input.trim();
        if filename.is_empty() {
            self.message = "Filename cannot be empty. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(BitQuillError::ValidationError("Empty filename".to_string()));
        }

        // Validate filename
        if filename.contains(|c: char| c == '/' || c == '\\' || c == ':' || c == '*' || 
                             c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            self.message = "Filename contains invalid characters. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(BitQuillError::ValidationError("Invalid filename characters".to_string()));
        }

        let mut save_path = self.file_browser.current_dir.clone();
        save_path.push(filename);

        // Ensure correct extension
        if save_path.extension().and_then(|e| e.to_str()) != Some(BITQUILL_FILE_EXT) {
            save_path.set_extension(BITQUILL_FILE_EXT);
        }

        // Ensure latest buffer changes are recorded
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }

        // Check if file exists and prompt for confirmation (not implemented yet)
        if save_path.exists() {
            // In a real implementation, we would prompt for confirmation
            // For now, we'll just overwrite
        }

        // Save document to the new path
        self.document.save_to_file(&save_path)?; // This resets dirty flag

        // Update app state
        self.file_path = Some(save_path.clone());
        self.add_to_recent_files(&save_path)?; // Update recent files

        // Close dialog and return to editing mode
        self.dialog = Dialog::None;
        self.mode = AppMode::Editing; // Return to editing after save
        self.file_browser.filename_input.clear();
        self.file_browser.is_editing_filename = false;
        self.file_browser.clear_filter()?; // Clear filter after dialog closes

        self.message = format!("Document saved to {}", save_path.display());
        self.last_auto_save = Instant::now(); // Reset auto-save timer
        Ok(())
    }

    // Trigger Open dialog state change
    pub fn trigger_open_dialog(&mut self) -> BitQuillResult<()> {
        if self.document.has_unsaved_changes() {
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::Open);
            self.message = "Save unsaved changes before opening?".to_string();
        } else {
            self.start_open_dialog()?;
        }
        Ok(())
    }

    // Actually starts the Open dialog UI
    pub fn start_open_dialog(&mut self) -> BitQuillResult<()> {
        self.mode = AppMode::FileDialog;
        self.dialog = Dialog::Open;
        self.file_browser.set_filter(BITQUILL_FILE_EXT)?; // Filter for .bq files
        self.file_browser.filename_input.clear(); // Not used for open
        self.file_browser.is_editing_filename = false;
        self.message = "Open File: Select a .bq file and press Enter.".to_string();
        Ok(())
    }

    // Confirm Open action from dialog input
    pub fn confirm_open(&mut self) -> BitQuillResult<()> {
        if let Some(path) = self.file_browser.get_selected_path() {
            if path.is_file() {
                // Ensure file has the correct extension before trying to load
                if path.extension().and_then(|e| e.to_str()) == Some(BITQUILL_FILE_EXT) {
                    // Load document
                    self.document.load_from_file(&path)?; // Load resets dirty flag

                    // Update buffer with loaded content
                    if !self.buffer.load_content(&self.document.get_current_content()) {
                        return Err(BitQuillError::ResourceExhaustedError(
                            "Document too large to load into buffer".to_string()
                        ));
                    }

                    // Update app state
                    self.file_path = Some(path.clone());
                    self.add_to_recent_files(&path)?;

                    // Close dialog and switch to editing mode
                    self.dialog = Dialog::None;
                    self.mode = AppMode::Editing; // Go to editing after open
                    self.file_browser.clear_filter()?;

                    self.message = format!("Document opened from {}", path.display());
                    Ok(())
                } else {
                    self.message = "Invalid file type. Please select a .bq file.".to_string();
                    Err(BitQuillError::ValidationError("Wrong file type".to_string()))
                }
            } else if path.is_dir() {
                // Navigate into directory
                match self.file_browser.enter_directory() {
                    Ok(_) => Ok(()),  // Stay in dialog mode after navigation
                    Err(e) => Err(e)
                }
            } else {
                // Should not happen if scan_directory is correct
                self.message = "Selected path is not a file or directory.".to_string();
                Err(BitQuillError::ValidationError("Invalid selection".to_string()))
            }
        } else {
            self.message = "No file or directory selected.".to_string();
            Err(BitQuillError::ValidationError("No selection".to_string()))
        }
    }

    // Trigger New document action (checking for unsaved changes)
    pub fn trigger_new_document(&mut self) -> BitQuillResult<()> {
        if self.document.has_unsaved_changes() {
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::New);
            self.message = "Save unsaved changes before creating a new document?".to_string();
        } else {
            self.confirm_new_document()?; // No unsaved changes, proceed directly
        }
        Ok(())
    }

    // Actually create the new document state
    pub fn confirm_new_document(&mut self) -> BitQuillResult<()> {
        // Record changes of the *old* document before discarding if needed
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }

        // Shutdown old VDF clock before replacing document
        self.document.shutdown();

        // Create new document state (this starts a new VDF clock)
        self.document = MerkleDocument::new()?;

        // Clear buffer and history
        self.buffer = TextBuffer::new(2000); // Recreate buffer too

        // Clear file path and reset status
        self.file_path = None;
        self.document.last_verification = None;

        self.dialog = Dialog::None; // Ensure no dialog is active
        self.mode = AppMode::Editing; // Go to editing mode

        self.message = "New document created".to_string();
        self.last_auto_save = Instant::now(); // Reset auto-save timer
        Ok(())
    }

    // Trigger verification action
    pub fn verify_document(&mut self, level: VerificationLevel) -> BitQuillResult<()> {
        // Record pending changes before verifying
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }
        
        // Update message BEFORE starting verification
        self.message = format!("Starting verification with {} leaves and {} nodes...", 
                             self.document.leaves.len(), 
                             self.document.nodes.len());
        
        // For consistency with original code, we don't propagate verification errors
        let result = self.document.verify_merkle_integrity(level);
        let leaf_count = self.document.leaves.len();
        let tick_count_mem = self.document.get_tick_count();

        if result.valid {
            self.message = format!("VERIFICATION PASSED ({:?}): {} leaves checked, {} nodes in tree, {} VDF ticks in memory.",
                                  level, leaf_count, self.document.nodes.len(), tick_count_mem);
        } else {
            self.message = format!("VERIFICATION FAILED ({:?}): Merkle tree integrity check failed! ({} leaves, {} nodes, {} ticks)",
                                  level, leaf_count, self.document.nodes.len(), tick_count_mem);
        }

        // Switch to verification detail view
        self.mode = AppMode::VerifyDetail;
        self.history_scroll = 0; // Reset scroll
        Ok(())
    }

    // Trigger Export dialog
    pub fn trigger_export_dialog(&mut self) -> BitQuillResult<()> {
        if self.document.leaves.is_empty() {
            self.message = "No leaves to export. Create some document history first.".to_string();
            return Ok(()); // Don't open dialog if nothing to export
        }

        self.mode = AppMode::FileDialog;
        self.dialog = Dialog::Export;
        self.file_browser.set_filter(BITQUILL_CHAIN_EXT)?; // Filter for .bqc
        
        // Suggest a default export filename based on the document name
        let default_export_name = self.file_path.as_ref()
            .map(|p| p.with_extension(BITQUILL_CHAIN_EXT))
            .and_then(|p| p.file_name().map(|n| n.to_os_string()))
            .and_then(|n| n.into_string().ok())
            .unwrap_or_else(|| "export.bqc".to_string());

        self.file_browser.filename_input = default_export_name;
        self.file_browser.is_editing_filename = true; // Start editing
        self.message = "Export Chain Data: Enter filename (.bqc) and press Enter.".to_string();
        Ok(())
    }

    // Confirm Export action from dialog
    pub fn confirm_export(&mut self) -> BitQuillResult<()> {
        let filename = self.file_browser.filename_input.trim();
        if filename.is_empty() {
            self.message = "Filename cannot be empty. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(BitQuillError::ValidationError("Empty filename".to_string()));
        }

        // Validate filename
        if filename.contains(|c: char| c == '/' || c == '\\' || c == ':' || c == '*' || 
                             c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            self.message = "Filename contains invalid characters. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(BitQuillError::ValidationError("Invalid filename characters".to_string()));
        }

        let mut export_path = self.file_browser.current_dir.clone();
        export_path.push(filename);

        // Ensure correct extension
        if export_path.extension().and_then(|e| e.to_str()) != Some(BITQUILL_CHAIN_EXT) {
            export_path.set_extension(BITQUILL_CHAIN_EXT);
        }

        // Export chain data
        self.document.export_chain_data(&export_path)?;

        // Close dialog and return to previous mode (usually Editing)
        self.dialog = Dialog::None;
        self.mode = AppMode::Editing; // Or whatever mode user was in before export
        self.file_browser.filename_input.clear();
        self.file_browser.is_editing_filename = false;
        self.file_browser.clear_filter()?;

        self.message = format!("Merkle tree data exported to {}", export_path.display());
        Ok(())
    }

    // Enter metadata editing mode
    pub fn trigger_edit_metadata(&mut self) -> BitQuillResult<()> {
        // Record pending buffer changes first
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }
        
        // Create metadata editor state with current metadata
        self.metadata_editor = Some(MetadataEditor::new(self.document.metadata.clone()));
        self.mode = AppMode::MetadataEdit;
        self.message = "Edit Metadata: Use Arrows, Enter to edit field, Ctrl+S to save, Esc to cancel.".to_string();
        Ok(())
    }

    // Save metadata changes from editor
    pub fn save_metadata(&mut self) -> BitQuillResult<()> {
        if let Some(editor) = &self.metadata_editor {
            // Check if metadata actually changed
            let new_metadata = editor.get_metadata();
            if new_metadata.title != self.document.metadata.title ||
               new_metadata.author != self.document.metadata.author ||
               new_metadata.keywords != self.document.metadata.keywords ||
               new_metadata.description != self.document.metadata.description {

                self.document.metadata = new_metadata;
                self.document.dirty = true; // Mark document dirty if metadata changed
                self.message = "Metadata updated and marked for saving.".to_string();
            } else {
                self.message = "Metadata unchanged.".to_string();
            }

            // Return to editing mode
            self.mode = AppMode::Editing;
            self.metadata_editor = None; // Clear editor state
        }
        Ok(())
    }

    // Cancel metadata editing
    pub fn cancel_metadata(&mut self) {
        // Return to editing mode without saving changes from editor
        self.mode = AppMode::Editing;
        self.metadata_editor = None;
        self.message = "Metadata editing cancelled".to_string();
    }

    // Toggle auto-save setting
    pub fn toggle_auto_save(&mut self) {
        self.auto_save_enabled = !self.auto_save_enabled;
        self.message = if self.auto_save_enabled {
            format!("Auto-save enabled (every {} seconds)", AUTO_SAVE_INTERVAL)
        } else {
            "Auto-save disabled".to_string()
        };
        self.last_auto_save = Instant::now(); // Reset timer when toggling
    }

    // Toggle line numbers in buffer
    pub fn toggle_line_numbers(&mut self) {
        self.buffer.toggle_line_numbers();
        self.message = if self.buffer.line_numbers {
            "Line numbers enabled".to_string()
        } else {
            "Line numbers disabled".to_string()
        };
    }

    // Request quit, checking for unsaved changes
    pub fn request_quit(&mut self) -> BitQuillResult<()> {
        // Ensure latest buffer changes are recorded if needed
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            match self.document.record_change(self.buffer.get_content()) {
                Ok(_) => self.buffer.record_history(),
                Err(e) => return Err(e)
            }
        }

        if self.document.has_unsaved_changes() {
            // Ask about unsaved changes first
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::Quit);
            self.message = "Save unsaved changes before quitting?".to_string();
        } else {
            // No unsaved changes, quit immediately
            self.should_quit = true;
        }
        Ok(())
    }

    // Handle confirmation for unsaved changes dialog ('Y' or 'N')
    pub fn handle_unsaved_dialog_confirm(&mut self, save_first: bool) -> BitQuillResult<()> {
        if let Dialog::UnsavedChanges(action) = self.dialog.clone() { // Clone action
            if save_first {
                // Attempt to save; if successful or no path (SaveAs triggered), proceed.
                // If save fails, stay in dialog.
                match self.save_document() {
                    Ok(_) => { // Saved successfully
                        self.proceed_with_action(action)?;
                    }
                    Err(e) if matches!(e, BitQuillError::StateError(ref s) if s == "Save As dialog triggered") => {
                        // Save As dialog is now active, don't proceed yet.
                        // User needs to complete Save As first.
                        self.message = "Please complete the Save As dialog.".to_string();
                    }
                    Err(e) => { // Other save error
                        self.message = format!("Error saving: {}. Action cancelled.", e);
                        // Stay in the UnsavedChanges dialog? Or cancel? Let's cancel.
                        self.dialog = Dialog::None;
                    }
                }
            } else {
                // Discard changes and proceed
                self.document.dirty = false; // Mark as not dirty explicitly
                self.proceed_with_action(action)?;
            }
        }
        Ok(())
    }

    // Proceeds with the original action after unsaved changes are handled
    pub fn proceed_with_action(&mut self, action: UnsavedAction) -> BitQuillResult<()> {
        match action {
            UnsavedAction::New => self.confirm_new_document()?,
            UnsavedAction::Open => self.start_open_dialog()?, // Start the open dialog now
            UnsavedAction::Quit => self.should_quit = true, // Quit now
            UnsavedAction::OpenRecent(index) => {
                // Need to re-trigger recent file opening after discard/save
                if let Err(e) = self.confirm_open_recent_file(index) {
                    self.message = format!("Error opening recent file: {}", e);
                }
            }
        }
        
        // Ensure dialog is closed unless another one was opened (like Save As)
        if self.dialog == Dialog::UnsavedChanges(action) {
            self.dialog = Dialog::None;
        }
        
        Ok(())
    }

    // Add path to recent files list and save
    pub fn add_to_recent_files(&mut self, path: &PathBuf) -> BitQuillResult<()> {
        // Ensure path is absolute for consistency
        let abs_path = match fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) => {
                // If can't canonicalize, just use the path as is
                eprintln!("Warning: Could not canonicalize path for recent files: {}", e);
                path.clone()
            }
        };

        // Remove if already exists to avoid duplicates and move to top
        self.recent_files.retain(|p| p != &abs_path);

        // Add to front
        self.recent_files.insert(0, abs_path);

        // Trim list
        self.recent_files.truncate(MAX_RECENT_FILES);

        // Save to config file
        self.save_recent_files()
    }

    // Load recent files list from config
    pub fn load_recent_files() -> BitQuillResult<Vec<PathBuf>> {
        let config_dir = utils::get_config_dir();
        let recent_files_path = config_dir.join("recent_files.txt");

        if !recent_files_path.exists() {
            return Ok(Vec::new());
        }

        match fs::read_to_string(&recent_files_path) {
            Ok(content) => {
                Ok(content.lines()
                    .map(PathBuf::from)
                    .filter(|p| p.exists()) // Only keep files that still exist
                    .take(MAX_RECENT_FILES)
                    .collect())
            },
            Err(e) => Err(BitQuillError::IoError(e))
        }
    }

    // Save recent files list to config
    pub fn save_recent_files(&self) -> BitQuillResult<()> {
        let config_dir = utils::get_config_dir();

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            match fs::create_dir_all(&config_dir) {
                Ok(_) => {},
                Err(e) => {
                    return Err(BitQuillError::IoError(e));
                }
            }
        }

        let recent_files_path = config_dir.join("recent_files.txt");

        // Convert paths to strings for saving
        let content = self.recent_files.iter()
            .map(|p| p.to_string_lossy().to_string()) // Use lossy conversion
            .collect::<Vec<_>>()
            .join("\n");

        // Save to file
        match fs::write(&recent_files_path, content) {
            Ok(_) => Ok(()),
            Err(e) => Err(BitQuillError::IoError(e))
        }
    }

    // Trigger opening a recent file
    pub fn trigger_open_recent_file(&mut self, index: usize) -> BitQuillResult<()> {
        if index >= self.recent_files.len() {
            self.message = format!("Invalid recent file number: {}", index + 1);
            return Err(BitQuillError::ValidationError(format!(
                "Invalid recent file index: {}", index + 1
            )));
        }

        if self.document.has_unsaved_changes() {
            // Ask about unsaved changes first
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::OpenRecent(index));
            self.message = "Save unsaved changes before opening recent file?".to_string();
        } else {
            // No unsaved changes, proceed directly
            if let Err(e) = self.confirm_open_recent_file(index) {
                self.message = format!("Error opening recent file: {}", e);
                return Err(e);
            }
        }
        
        Ok(())
    }

    // Actually load the recent file
    pub fn confirm_open_recent_file(&mut self, index: usize) -> BitQuillResult<()> {
        if index >= self.recent_files.len() {
            return Err(BitQuillError::ValidationError(format!(
                "Recent file index out of bounds: {}", index
            )));
        }

        let path = self.recent_files[index].clone(); // Clone to avoid borrow issues

        // Verify the file still exists
        if !path.exists() {
            // Remove from recent files list
            self.recent_files.remove(index);
            self.save_recent_files()?;
            
            return Err(BitQuillError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Recent file not found: {}", path.display())
            )));
        }

        // Load document
        self.document.load_from_file(&path)?;

        // Update buffer with loaded content
        if !self.buffer.load_content(&self.document.get_current_content()) {
            return Err(BitQuillError::ResourceExhaustedError(
                "Document too large to load into buffer".to_string()
            ));
        }

        // Update app state
        self.file_path = Some(path.clone());
        self.add_to_recent_files(&path)?; // Move to top of recent list

        // Ensure correct mode and clear dialog
        self.mode = AppMode::Editing;
        self.dialog = Dialog::None;

        self.message = format!("Opened recent file {}", path.display());
        Ok(())
    }
    
    // Get help text content
    fn get_help_text(&self) -> Vec<String> {
        vec![
            "BitQuill Merkle Edition Commands:".to_string(),
            "".to_string(),
            "File Operations:".to_string(),
            "  F1           - Show/Hide Help".to_string(),
            "  Ctrl+S       - Save Document".to_string(),
            "  Ctrl+Shift+S - Save As...".to_string(),
            "  Ctrl+O       - Open Document".to_string(),
            "  Ctrl+N       - New Document".to_string(),
            "  Ctrl+E       - Export Merkle Tree Data (.bqc)".to_string(),
            "  Ctrl+M       - Edit Metadata".to_string(),
            "  Alt+1..9     - Open Recent File (1-based)".to_string(),
            "  Alt+A        - Toggle Auto-Save".to_string(),
            "".to_string(),
            "Navigation & Modes:".to_string(),
            "  Tab / F2     - Toggle Edit / View Mode".to_string(),
            "  F3           - Toggle Tree View (from View mode)".to_string(),
            "  Arrow Keys   - Move Cursor (Edit) / Select (View/Dialog)".to_string(),
            "  Home/End     - Move to Start/End of Line (Edit)".to_string(),
            "  PgUp/PgDn    - Page Up/Down (Edit/View)".to_string(),
            "  Alt+L        - Toggle Line Numbers".to_string(),
            "".to_string(),
            "Editing:".to_string(),
            "  Enter        - New Line / Confirm Dialog Action".to_string(),
            "  Backspace    - Delete Character Behind Cursor".to_string(),
            "  Ctrl+Z       - Undo (basic)".to_string(),
              "".to_string(),
            "Search & Replace:".to_string(),
            "  Ctrl+F       - Find Text".to_string(),
            "  Ctrl+H       - Find and Replace".to_string(),
            "  Ctrl+N       - Find Next Match".to_string(),
            "  Ctrl+P       - Find Previous Match".to_string(),
            "  Ctrl+R       - Replace Current Match".to_string(),
            "  Ctrl+A       - Replace All Matches".to_string(),
            "  F5       - Toggle Case Sensitivity".to_string(),
            "".to_string(),
            "Verification:".to_string(),
            "  Ctrl+V       - Verify Merkle Tree Integrity".to_string(),
            "".to_string(),
            "Dialogs:".to_string(),
            "  Esc          - Cancel Current Action / Dialog / Quit".to_string(),
            "  Y / N        - Confirm Yes/No Dialogs".to_string(),
            "  F / Tab      - Focus Filename Input (in File Dialog)".to_string(),
            "".to_string(),
            "About BitQuill Merkle Edition:".to_string(),
            " Creates a tamper-evident document history using a".to_string(),
            " Merkle tree structure with VDF-based time attestation.".to_string(),
            " Each leaf represents a document state, providing an".to_string(),
            " efficient verification structure for document history.".to_string(),
        ]
    }
    
    
       // Start a search operation
    pub fn start_search(&mut self, replace_mode: bool) -> BitQuillResult<()> {
        if self.mode != AppMode::Editing {
            // Only allow search from editing mode
            self.message = "Search only available in Editing mode".to_string();
            return Ok(());
        }
        
        self.search_state.is_active = true;
        self.search_state.is_replace_mode = replace_mode;
        self.search_state.reset();
        self.mode = AppMode::Search;
        
        let action = if replace_mode { "Replace" } else { "Search" };
        self.message = format!("{}: Enter search text and press Enter", action);
        
        Ok(())
    }
    
    // Execute the search
    pub fn execute_search(&mut self) -> BitQuillResult<()> {
        if self.search_state.search_query.is_empty() {
            self.message = "Search query cannot be empty".to_string();
            return Ok(());
        }
        
        // Find all matches
        let matches = self.buffer.find_all(
            &self.search_state.search_query,
            self.search_state.case_sensitive
        );
        
        if matches.is_empty() {
            self.message = format!("No matches found for '{}'", self.search_state.search_query);
            self.search_state.reset();
        } else {
            self.search_state.current_matches = matches.clone();
            self.search_state.current_match_idx = Some(0);
            
            // Go to the first match
            self.go_to_current_match();
            
            self.message = format!(
                "Found {} matches for '{}'",
                self.search_state.current_matches.len(),
                self.search_state.search_query
            );
        }
        
        Ok(())
    }
    
    // Navigate to the current match
    pub fn go_to_current_match(&mut self) {
        if let Some(idx) = self.search_state.current_match_idx {
            if idx < self.search_state.current_matches.len() {
                let matched_pos = self.search_state.current_matches[idx];
                self.buffer.move_to_match(matched_pos);
            }
        }
    }
    
    // Go to next match
    pub fn find_next(&mut self) -> BitQuillResult<()> {
        if self.search_state.current_matches.is_empty() {
            // No matches to navigate
            self.message = "No matches to navigate".to_string();
            return Ok(());
        }
        
        let next_idx = match self.search_state.current_match_idx {
            Some(idx) => (idx + 1) % self.search_state.current_matches.len(),
            None => 0,
        };
        
        self.search_state.current_match_idx = Some(next_idx);
        self.go_to_current_match();
        
        self.message = format!(
            "Match {}/{} for '{}'",
            next_idx + 1,
            self.search_state.current_matches.len(),
            self.search_state.search_query
        );
        
        Ok(())
    }
    
    // Go to previous match
    pub fn find_prev(&mut self) -> BitQuillResult<()> {
        if self.search_state.current_matches.is_empty() {
            // No matches to navigate
            self.message = "No matches to navigate".to_string();
            return Ok(());
        }
        
        let total = self.search_state.current_matches.len();
        let prev_idx = match self.search_state.current_match_idx {
            Some(idx) => (idx + total - 1) % total,
            None => total - 1,
        };
        
        self.search_state.current_match_idx = Some(prev_idx);
        self.go_to_current_match();
        
        self.message = format!(
            "Match {}/{} for '{}'",
            prev_idx + 1,
            self.search_state.current_matches.len(),
            self.search_state.search_query
        );
        
        Ok(())
    }
    
    // Replace current match and move to next
    pub fn replace_current(&mut self) -> BitQuillResult<()> {
        if !self.search_state.is_replace_mode || self.search_state.current_matches.is_empty() {
            return Ok(());
        }
        
        if let Some(idx) = self.search_state.current_match_idx {
            if idx < self.search_state.current_matches.len() {
                let matched_pos = self.search_state.current_matches[idx];
                if self.buffer.replace_match(matched_pos, &self.search_state.replace_text) {
                    // Mark document as dirty
                    self.document.dirty = true;
                    
                    // Refresh the matches as positions have changed
                    self.refresh_search()?;
                    
                    self.message = "Replaced match and moved to next".to_string();
                } else {
                    self.message = "Failed to replace match".to_string();
                }
            }
        }
        
        Ok(())
    }
    
    // Replace all matches at once
    pub fn replace_all(&mut self) -> BitQuillResult<()> {
        if !self.search_state.is_replace_mode || self.search_state.current_matches.is_empty() {
            return Ok(());
        }
        
        let count = self.buffer.replace_all(
            &self.search_state.current_matches,
            &self.search_state.replace_text
        );
        
        // Mark document as dirty
        self.document.dirty = true;
        
        // Clear matches since they've all been replaced
        self.search_state.reset();
        
        self.message = format!("Replaced {} occurrences", count);
        
        Ok(())
    }
    
    // Refresh search matches after editing text
    pub fn refresh_search(&mut self) -> BitQuillResult<()> {
        if self.search_state.is_active && !self.search_state.search_query.is_empty() {
            let current_idx = self.search_state.current_match_idx;
            
            // Re-run the search to get updated positions
            let matches = self.buffer.find_all(
                &self.search_state.search_query,
                self.search_state.case_sensitive
            );
            
            if matches.is_empty() {
                self.search_state.reset();
                self.message = "No more matches after edit".to_string();
            } else {
                self.search_state.current_matches = matches.clone();
                
                // Try to maintain the current match index if possible
                if let Some(idx) = current_idx {
                    if idx < matches.len() {
                        self.search_state.current_match_idx = Some(idx);
                    } else {
                        self.search_state.current_match_idx = Some(0);
                    }
                } else {
                    self.search_state.current_match_idx = Some(0);
                }
                
                self.go_to_current_match();
            }
        }
        
        Ok(())
    }
    
    // Toggle case sensitivity for search
    pub fn toggle_case_sensitivity(&mut self) -> BitQuillResult<()> {
        self.search_state.case_sensitive = !self.search_state.case_sensitive;
        
        // Re-run search with new case sensitivity setting
        if self.search_state.is_active && !self.search_state.search_query.is_empty() {
            self.refresh_search()?;
        }
        
        self.message = format!(
            "Case sensitivity: {}",
            if self.search_state.case_sensitive { "On" } else { "Off" }
        );
        
        Ok(())
    }
    
    // Exit search mode
    pub fn exit_search(&mut self) -> BitQuillResult<()> {
        self.mode = AppMode::Editing;
        self.search_state.is_active = false;
        self.message = "Search/Replace closed".to_string();
        Ok(())
    }

    // Perform undo action
    pub fn undo(&mut self) -> BitQuillResult<()> {
        if self.mode == AppMode::Editing {
            if self.buffer.undo() {
                // After undo, the buffer content has changed, mark document dirty
                self.document.dirty = true;
                self.message = "Undo performed".to_string();
            } else {
                self.message = "Nothing to undo".to_string();
            }
        } else {
            self.message = "Undo only available in Editing mode".to_string();
        }
        
        Ok(())
    }

    // Prepare for shutdown
    pub fn shutdown(&mut self) {
        // Record any final changes before shutdown
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            if let Err(e) = self.document.record_change(self.buffer.get_content()) {
                eprintln!("Error recording final changes: {}", e);
            }
        }

        // Shutdown VDF clock thread
        self.document.shutdown();
        
        // Save recent files one last time
        if let Err(e) = self.save_recent_files() {
            eprintln!("Error saving recent files during shutdown: {}", e);
        }
    }
}    
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
