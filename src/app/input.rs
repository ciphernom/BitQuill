use crate::app::{App, AppMode, Dialog};

use crate::error::BitQuillResult;
use crate::merkle::VerificationLevel;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};


// Process key events with error handling
pub fn process_key_event(app: &mut App, key: KeyEvent) -> BitQuillResult<()> {
    // 1. Handle Dialog Input (if any dialog is active)
    if app.dialog != Dialog::None {
        if handle_dialog_input(app, key)? {
            return Ok(());  // Key was handled by dialog
        }
    }

    // 2. Handle Mode-Specific Input
    if match app.mode {
        AppMode::Editing => handle_editing_input(app, key)?,
        AppMode::Viewing => handle_viewing_input(app, key)?,
        AppMode::VerifyDetail => handle_verify_detail_input(app, key)?,
        AppMode::TreeView => handle_tree_view_input(app, key)?,
        AppMode::MetadataEdit => handle_metadata_edit_input(app, key)?,
        AppMode::Help => handle_help_input(app, key)?,
        AppMode::Search => handle_search_input(app, key)?,
        AppMode::FileDialog => false, // Should be handled by dialog handling above
    } {
        return Ok(());  // Key was handled by mode-specific handler
    }

    // 3. Handle Global Input
    handle_global_input(app, key).map(|_| ())  // Map the bool result to ()
}

// Handle input when a dialog is active
fn handle_dialog_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match &app.dialog {
        Dialog::SaveAs | Dialog::Export => {
            match key.code {
                KeyCode::Esc => {
                    app.dialog = Dialog::None;
                    app.mode = AppMode::Editing; // Go back to editing on cancel
                    app.file_browser.clear_filter()?;
                    app.message = "Save As / Export cancelled.".to_string();
                    Ok(true) // Handled
                }
                KeyCode::Enter => {
                    if app.file_browser.is_editing_filename {
                        // Finish editing filename, attempt confirm
                        app.file_browser.is_editing_filename = false;
                        if app.dialog == Dialog::SaveAs { 
                            let _ = app.confirm_save_as(); 
                        } else { 
                            let _ = app.confirm_export(); 
                        }
                        Ok(true)
                    } else {
                        // Try to enter directory or confirm file selection
                        match app.file_browser.enter_directory() {
                            Ok(entered) => {
                                if !entered {
                                    // Not a directory, try to confirm
                                    if app.dialog == Dialog::SaveAs { 
                                        let _ = app.confirm_save_as(); 
                                    } else { 
                                        let _ = app.confirm_export(); 
                                    }
                                }
                                Ok(true)
                            },
                            Err(e) => {
                                app.message = format!("Error navigating directory: {}", e);
                                Ok(true)
                            }
                        }
                    }
                }
                KeyCode::Up => { 
                    if !app.file_browser.is_editing_filename { 
                        app.file_browser.navigate_up(); 
                    } 
                    Ok(true) 
                }
                KeyCode::Down => { 
                    if !app.file_browser.is_editing_filename { 
                        app.file_browser.navigate_down(); 
                    } 
                    Ok(true) 
                }
                KeyCode::Tab | KeyCode::Char('f') | KeyCode::Char('F') => { // F or Tab to focus filename input
                    app.file_browser.is_editing_filename = !app.file_browser.is_editing_filename;
                    Ok(true)
                }
                KeyCode::Char(c) if app.file_browser.is_editing_filename => {
                    app.file_browser.add_to_filename(c);
                    Ok(true)
                }
                KeyCode::Backspace if app.file_browser.is_editing_filename => {
                    app.file_browser.filename_input.pop();
                    Ok(true)
                }
                _ => Ok(false) // Not handled by this dialog
            }
        }
        Dialog::Open => {
            match key.code {
                KeyCode::Esc => {
                    app.dialog = Dialog::None;
                    app.mode = AppMode::Editing;
                    app.file_browser.clear_filter()?;
                    app.message = "Open cancelled.".to_string();
                    Ok(true) // Handled
                }
                KeyCode::Enter => {
                    // Try to enter directory or confirm file selection
                    match app.file_browser.enter_directory() {
                        Ok(entered) => {
                            if !entered {
                                // Not a directory, try to open
                                let _ = app.confirm_open();
                            }
                            Ok(true)
                        },
                        Err(e) => {
                            app.message = format!("Error navigating directory: {}", e);
                            Ok(true)
                        }
                    }
                }
                KeyCode::Up => { app.file_browser.navigate_up(); Ok(true) }
                KeyCode::Down => { app.file_browser.navigate_down(); Ok(true) }
                _ => Ok(false) // Not handled by this dialog
            }
        }
        Dialog::UnsavedChanges(_) => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    app.handle_unsaved_dialog_confirm(true)?; // Save first
                    Ok(true)
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    app.handle_unsaved_dialog_confirm(false)?; // Discard changes
                    Ok(true)
                }
                KeyCode::Esc => {
                    app.dialog = Dialog::None; // Cancel the action
                    app.message = "Action cancelled.".to_string();
                    Ok(true)
                }
                _ => Ok(false)
            }
        }
        Dialog::None | Dialog::NewConfirm | Dialog::Metadata => Ok(false), // These are handled elsewhere
    }
}

// Handle input in Editing mode
fn handle_editing_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    // Ctrl+key combinations handled globally
    if key.modifiers.contains(KeyModifiers::CONTROL) { return Ok(false); }
    // Alt+key combinations handled globally
    if key.modifiers.contains(KeyModifiers::ALT) { return Ok(false); }

    match key.code {
        KeyCode::Enter => { 
            // First capture the current paragraph's text
            let current_line_idx = app.buffer.cursor_row;
            if current_line_idx < app.buffer.lines.len() {
                let paragraph_content = app.buffer.lines[current_line_idx].clone();
                
                // Then insert the newline normally
                if app.insert_char('\n') {
                    // Create a new leaf with just the paragraph content
                    if let Some(tick) = app.document.latest_tick.clone() {
                        // Record only this paragraph's content
                        if let Err(e) = app.document.record_paragraph(paragraph_content) {
                            app.message = format!("Error recording paragraph: {}", e);
                            return Ok(true);
                        }
                        
                        if let Err(e) = app.document.create_leaf(tick.sequence_number) {
                            app.message = format!("Error creating leaf: {}", e);
                            return Ok(true);
                        }
                        
                        app.message = format!("New paragraph #{} created (VDF tick #{})", 
                                            app.document.leaves.len(), tick.sequence_number);
                    }
                }
            }
            Ok(true) 
        },
        KeyCode::Char(c) => { app.insert_char(c); Ok(true) },
        KeyCode::Backspace => { app.delete_char(); Ok(true) },
        KeyCode::Left => { app.buffer.move_cursor_left(); Ok(true) },
        KeyCode::Right => { app.buffer.move_cursor_right(); Ok(true) },
        KeyCode::Up => { app.buffer.move_cursor_up(); Ok(true) },
        KeyCode::Down => { app.buffer.move_cursor_down(); Ok(true) },
        KeyCode::Home => { app.buffer.move_cursor_home(); Ok(true) },
        KeyCode::End => { app.buffer.move_cursor_end(); Ok(true) },
        KeyCode::PageUp => { app.buffer.page_up(20); Ok(true) }, // Use reasonable height
        KeyCode::PageDown => { app.buffer.page_down(20); Ok(true) },
        KeyCode::Tab | KeyCode::F(2) => { app.toggle_edit_view_mode(); Ok(true) }, // F2 as alternative toggle
        KeyCode::F(1) => { app.toggle_help(); Ok(true) }, // F1 handled globally too, but can be mode specific
        _ => Ok(false) // Not handled by editing mode specifically
    }
}

// Handle input in Viewing mode (Leaf History)
fn handle_viewing_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            Ok(true) 
        },
        KeyCode::Down => { 
            // Increase scroll with bounds checking
            if app.history_scroll + 1 < app.document.leaves.len() {
                app.history_scroll += 1;
            }
            Ok(true) 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            Ok(true) 
        },
        KeyCode::PageDown => { 
            // Increase scroll with bounds checking
            let max_scroll = app.document.leaves.len().saturating_sub(1);
            app.history_scroll = (app.history_scroll + 10).min(max_scroll);
            Ok(true) 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            Ok(true) 
        },
        KeyCode::End => { 
            // Set to last leaf (with bounds checking)
            app.history_scroll = app.document.leaves.len().saturating_sub(1);
            Ok(true) 
        },
        KeyCode::Tab | KeyCode::F(2) => { 
            app.toggle_edit_view_mode(); 
            Ok(true) 
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            Ok(true) 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            Ok(true) 
        },
        KeyCode::Enter => { // Toggle back to editing
            app.toggle_edit_view_mode();
            Ok(true)
        },
        _ => Ok(false)
    }
}

// Handle input in Tree View mode
fn handle_tree_view_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            Ok(true) 
        },
        KeyCode::Down => { 
            // Increase with bounds checking against tree structure size
            let tree_lines = app.document.get_tree_structure();
            if app.history_scroll + 1 < tree_lines.len() {
                app.history_scroll += 1;
            }
            Ok(true) 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            Ok(true) 
        },
        KeyCode::PageDown => { 
            // Increase with bounds checking
            let tree_lines = app.document.get_tree_structure();
            let max_scroll = tree_lines.len().saturating_sub(1);
            app.history_scroll = (app.history_scroll + 10).min(max_scroll);
            Ok(true) 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            Ok(true) 
        },
        KeyCode::End => {
            // Set to last tree line (with bounds checking)
            let tree_lines = app.document.get_tree_structure();
            app.history_scroll = tree_lines.len().saturating_sub(1);
            Ok(true)
        },
        KeyCode::Tab | KeyCode::F(2) => { 
            app.toggle_edit_view_mode(); 
            Ok(true) 
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            Ok(true) 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            Ok(true) 
        },
        KeyCode::Enter | KeyCode::Esc => {
            app.toggle_tree_view(); // Return to viewing mode
            Ok(true)
        },
        _ => Ok(false)
    }
}

// Handle input in Verify Detail mode
fn handle_verify_detail_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            Ok(true) 
        },
        KeyCode::Down => { 
            // Increase with bounds checking
            if let Some(v) = &app.document.last_verification {
                if app.history_scroll + 1 < v.details.len() + 2 { // +2 for header lines
                    app.history_scroll += 1;
                }
            }
            Ok(true) 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            Ok(true) 
        },
        KeyCode::PageDown => { 
            // Increase with bounds checking
            if let Some(v) = &app.document.last_verification {
                let max_scroll = (v.details.len() + 2).saturating_sub(1); // +2 for header lines
                app.history_scroll = (app.history_scroll + 10).min(max_scroll);
            }
            Ok(true) 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            Ok(true) 
        },
        KeyCode::End => {
            // Set to last verification detail (with bounds checking)
            if let Some(v) = &app.document.last_verification {
                app.history_scroll = (v.details.len() + 2).saturating_sub(1); // +2 for header lines
            }
            Ok(true)
        },
        KeyCode::Tab | KeyCode::F(2) | KeyCode::Enter | KeyCode::Esc => {
            // Any of these return to Viewing mode from verification details
            app.mode = AppMode::Viewing;
            app.history_scroll = 0; // Reset scroll for viewing mode
            app.message = "Returned to Viewing mode.".to_string();
            Ok(true)
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            Ok(true) 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            Ok(true) 
        },
        _ => Ok(false)
    }
}

// Handle input in Metadata Edit mode
fn handle_metadata_edit_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    if let Some(editor) = app.metadata_editor.as_mut() {
        if editor.editing {
            // Pass input directly to editor buffer handling
            if editor.handle_edit_key(key.code) {
                return Ok(true); // Handled by editor buffer
            } else {
                return Ok(false); // Not handled by editor buffer
            }
        } else {
            // Handle navigation between fields or starting edit
            match key.code {
                KeyCode::Up => { editor.navigate_up(); Ok(true) },
                KeyCode::Down => { editor.navigate_down(); Ok(true) },
                KeyCode::Enter => { editor.start_editing(); Ok(true) },
                KeyCode::Esc => { app.cancel_metadata(); Ok(true) },
                // Ctrl+S handled globally
                KeyCode::F(1) => { app.toggle_help(); Ok(true) },
                _ => Ok(false)
            }
        }
    } else {
        // Should not be in this mode without an editor, switch back
        app.mode = AppMode::Editing;
        Ok(false)
    }
}

// Handle input in Help mode
fn handle_help_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match key.code {
        KeyCode::F(1) | KeyCode::Esc => {
            app.toggle_help();
            Ok(true)
        },
        KeyCode::Up => { Ok(true) }, // Placeholder for scrolling
        KeyCode::Down => { Ok(true) },
        _ => Ok(false) // Ignore other keys in help mode
    }
}

// Handle input in Search mode
fn handle_search_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    // Check for Ctrl+key combinations
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = key.code {
            match c {
                'n' => {
                    app.find_next()?;
                    return Ok(true);
                },
                'p' => {
                    app.find_prev()?;
                    return Ok(true);
                },
                'r' => {
                    if app.search_state.is_replace_mode {
                        app.replace_current()?;
                    }
                    return Ok(true);
                },
                'a' => {
                    if app.search_state.is_replace_mode {
                        app.replace_all()?;
                    }
                    return Ok(true);
                },
                _ => {} // Other Ctrl combinations
            }
        }
    }

    // Handle non-modifier keys
    match key.code {
        KeyCode::Esc => {
            app.exit_search()?;
            Ok(true)
        },
        KeyCode::Enter => {
            if app.search_state.search_query.is_empty() {
                if app.search_state.is_replace_mode && !app.search_state.replace_text.is_empty() {
                    // Switch to entering search query
                    app.search_state.replace_text.clear();
                    app.message = "Search: Enter search text and press Enter".to_string();
                    Ok(true)
                } else {
                    app.exit_search()?;
                    Ok(true)
                }
            } else if app.search_state.is_replace_mode && app.search_state.replace_text.is_empty() {
                // In replace mode, after entering search query, prompt for replace text
                app.execute_search()?;
                app.message = "Replace: Enter replacement text and press Enter".to_string();
                Ok(true)
            } else {
                // Execute the search or confirm replace text
                app.execute_search()?;
                Ok(true)
            }
        },
        KeyCode::Backspace => {
            if app.search_state.is_replace_mode && !app.search_state.search_query.is_empty() {
                // Editing replace text
                app.search_state.replace_text.pop();
            } else {
                // Editing search query
                app.search_state.search_query.pop();
            }
            Ok(true)
        },
        KeyCode::Down => {
            app.find_next()?;
            Ok(true)
        },
        KeyCode::Up => {
            app.find_prev()?;
            Ok(true)
        },
        KeyCode::F(5) => {
            app.toggle_case_sensitivity()?;
            Ok(true)
        },
        KeyCode::Char(c) => {
            if app.search_state.is_replace_mode && !app.search_state.search_query.is_empty() {
                // Entering replace text
                if !app.search_state.safely_add_to_replace(c) {
                    app.message = "Replace text too long".to_string();
                }
            } else {
                // Entering search query
                if !app.search_state.safely_add_to_query(c) {
                    app.message = "Search query too long".to_string();
                }
            }
            Ok(true)
        },
        _ => Ok(false),
    }
}

// Handle global input shortcuts (like Ctrl+S, Ctrl+O, etc.)
fn handle_global_input(app: &mut App, key: KeyEvent) -> BitQuillResult<bool> {
    match key.code {
        // --- Ctrl Keybindings ---
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.trigger_save_as_dialog()?;
            } else if app.mode == AppMode::MetadataEdit {
                app.save_metadata()?;
            } else {
                match app.save_document() {
                    Ok(_) => {},
                    Err(e) if matches!(e, crate::error::BitQuillError::StateError(ref s) if s == "Save As dialog triggered") => {
                        // Expected when no file path is set yet
                    },
                    Err(e) => {
                        app.message = format!("Error saving: {}", e);
                    }
                }
            }
            Ok(true)
        },
        KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_open_dialog()?;
            Ok(true)
        },
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.mode == AppMode::Search {
                app.find_next()?;
            } else {
                app.trigger_new_document()?;
            }
            Ok(true)
        },
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.verify_document(VerificationLevel::Standard)?;
            Ok(true)
        },
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_export_dialog()?;
            Ok(true)
        },
        KeyCode::Char('m') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_edit_metadata()?;
            Ok(true)
        },
        KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.undo()?;
            Ok(true)
        },
        KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+F for search
            app.start_search(false)?;
            Ok(true)
        },
        KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Ctrl+H for replace
            app.start_search(true)?;
            Ok(true)
        },
        KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if app.mode == AppMode::Search || 
               (app.search_state.is_active && app.mode == AppMode::Editing) {
                app.find_prev()?;
                Ok(true)
            } else {
                Ok(false)
            }
        },
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) && app.mode == AppMode::Search => {
            if app.search_state.is_replace_mode {
                app.replace_current()?;
            }
            Ok(true)
        },
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) && app.mode == AppMode::Search => {
            if app.search_state.is_replace_mode {
                app.replace_all()?;
            }
            Ok(true)
        },
        
        // --- Alt Keybindings ---
        KeyCode::Char(c @ '1'..='9') if key.modifiers.contains(KeyModifiers::ALT) => {
            let index = (c as u8 - b'1') as usize; // 1-based index
            match app.trigger_open_recent_file(index) {
                Ok(_) => Ok(true),
                Err(e) => {
                    app.message = format!("Error opening recent file: {}", e);
                    Ok(true)
                }
            }
        },
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::ALT) => {
            app.toggle_auto_save();
            Ok(true)
        },
        KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::ALT) => {
            app.toggle_line_numbers();
            Ok(true)
        },
        
        // --- F-Key Bindings ---
        KeyCode::F(1) => { // F1 global toggle for help
            app.toggle_help();
            Ok(true)
        },
        KeyCode::F(2) => { // F2 global toggle for edit/view mode
            if app.mode == AppMode::Editing || app.mode == AppMode::Viewing {
                app.toggle_edit_view_mode();
                Ok(true)
            } else {
                Ok(false)
            }
        },
        KeyCode::F(3) => { // F3 toggle tree view
            if app.mode == AppMode::Viewing || app.mode == AppMode::VerifyDetail || app.mode == AppMode::TreeView {
                app.toggle_tree_view();
                Ok(true)
            } else {
                Ok(false)
            }
        },
        KeyCode::F(5) if app.mode == AppMode::Search => {
            app.toggle_case_sensitivity()?;
            Ok(true)
        },
        // --- Other Global Keys ---
        KeyCode::Esc => { // Global Esc for quit/cancel
            if app.mode == AppMode::Search {
                app.exit_search()?;
                Ok(true)
            } else {
                match app.request_quit() {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        app.message = format!("Error when attempting to quit: {}", e);
                        Ok(true)
                    }
                }
            }
        },
        _ => Ok(false) // Not a global keybinding
    }
}
