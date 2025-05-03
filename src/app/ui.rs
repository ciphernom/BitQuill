use crate::app::{App, AppMode, Dialog, UnsavedAction};
use crate::utils;

use std::io;
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Line},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

// Main UI rendering function
pub fn ui(f: &mut Frame<CrosstermBackend<io::Stdout>>, app: &mut App) {
    let size = f.size();

    // Main layout (Status, Indicator, Message, Content)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(0) // No outer margin
        .constraints(
            [
                Constraint::Length(1), // Status line
                Constraint::Length(1), // VDF Indicator line
                Constraint::Length(3), // Message bar
                Constraint::Min(0),    // Main content area
            ]
            .as_ref(),
        )
        .split(size);

    // --- Status Line ---
    let chain_status = match &app.document.last_verification {
        Some(v) if v.valid => Style::default().fg(Color::Green),
        Some(_) => Style::default().fg(Color::Red),
        None => Style::default().fg(Color::DarkGray),
    };
    
    let chain_text = match &app.document.last_verification {
        Some(v) if v.valid => "✓ Valid",
        Some(_) => "✗ Invalid",
        None => "? Unknown",
    };
    
    let cursor_pos = app.buffer.get_cursor_position();
    
    let file_name = app.file_path.as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("Untitled");
        
    let dirty_indicator = if app.document.has_unsaved_changes() { "*" } else { "" };
    let auto_save_status = if app.auto_save_enabled { ("On", Color::Green) } else { ("Off", Color::Red) };
    
    let mode_text = match app.mode {
        AppMode::Editing => "EDITING",
        AppMode::Viewing => "VIEWING HISTORY",
        AppMode::VerifyDetail => "VERIFY DETAILS",
        AppMode::TreeView => "TREE VIEW",
        AppMode::FileDialog => "FILE DIALOG",
        AppMode::MetadataEdit => "EDIT METADATA",
        AppMode::Help => "HELP",
        AppMode::Search => "SEARCH", 
    };

    let status_spans = Line::from(vec![
        Span::styled("BitQuill", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled(format!("Mode: {}", mode_text), Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled(format!("File: {}{}", file_name, dirty_indicator), Style::default().fg(Color::Magenta)),
        Span::raw(" | "),
        Span::styled(format!("Ln {}, Col {}", cursor_pos.0, cursor_pos.1), Style::default().fg(Color::LightBlue)),
        Span::raw(" | "),
        Span::styled(format!("Tree: {}", chain_text), chain_status),
        Span::raw(" | "),
        Span::styled(format!("Leaves: {}", app.document.leaves.len()), Style::default().fg(Color::Blue)),
        Span::raw(" | "),
        Span::styled(format!("AutoSave: {}", auto_save_status.0), Style::default().fg(auto_save_status.1)),
    ]);
    
    let status_bar = Paragraph::new(status_spans).style(Style::default().bg(Color::DarkGray)); // Status bar background
    f.render_widget(status_bar, chunks[0]);

    // --- VDF Tick Indicator ---
    let tick_indicator_text = if app.show_tick_indicator {
        let tick_num = app.document.latest_tick.as_ref().map_or(0, |t| t.sequence_number);
        format!(" VDF Tick #{} Processed ", tick_num)
    } else {
        format!(" VDF Clock Running (Tick #{}) ", 
                app.document.latest_tick.as_ref().map_or(0, |t| t.sequence_number))
    };
    
    let indicator_style = if app.show_tick_indicator { 
        Style::default().fg(Color::Black).bg(Color::Yellow) 
    } else { 
        Style::default().fg(Color::DarkGray) 
    };
    
    let indicator = Paragraph::new(Span::styled(tick_indicator_text, indicator_style));
    f.render_widget(indicator, chunks[1]);

    // --- Message Bar ---
    let message_block = Block::default().borders(Borders::ALL).title("Status");
    let message_area = message_block.inner(chunks[2]); // Get inner area for text
    
    // Ensure message doesn't exceed safe length
    let safe_message = if app.message.len() > 500 {
        format!("{}...", &app.message[..497])
    } else {
        app.message.clone()
    };
    
    let message = Paragraph::new(safe_message)
        .style(Style::default().fg(Color::White))
        .wrap(tui::widgets::Wrap { trim: true }); // Wrap long messages
        
    f.render_widget(message_block, chunks[2]);
    f.render_widget(message, message_area);

    // --- Main Content Area ---
    let content_area = chunks[3];

    // Render Dialogs First (if active) - they overlay the main content
    match &app.dialog {
        Dialog::SaveAs => {
            render_file_dialog(f, content_area, app, "Save Document As (.bq)", true);
            return; // Stop rendering normal UI if dialog is shown
        },
        Dialog::Open => {
            render_file_dialog(f, content_area, app, "Open Document (.bq)", false);
            return;
        },
        Dialog::Export => {
            render_file_dialog(f, content_area, app, "Export Merkle Tree Data (.bqc)", true);
            return;
        },
        Dialog::UnsavedChanges(_) => {
            render_unsaved_dialog(f, content_area, app);
            return;
        },
        // Other dialogs removed or handled differently
        Dialog::None | Dialog::NewConfirm | Dialog::Metadata => {} // Continue rendering normal mode
    }

    // Render based on current AppMode
    match app.mode {
        AppMode::Editing => {
            render_editing_mode(f, content_area, app);
        },
        AppMode::Viewing => {
            render_viewing_mode(f, content_area, app);
        },
        AppMode::TreeView => {
            render_tree_view_mode(f, content_area, app);
        },
        AppMode::VerifyDetail => {
            render_verify_detail_mode(f, content_area, app);
        },
        AppMode::MetadataEdit => {
            render_metadata_editor(f, content_area, app);
        },
        AppMode::Help => {
            render_help_screen(f, content_area, app);
        },
        AppMode::Search => {
            render_search_ui(f, content_area, app);
        },
        AppMode::FileDialog => {
            // This case should ideally be handled by the dialog rendering at the start
            let error_block = Block::default().borders(Borders::ALL).title("Error");
            let inner_area = error_block.inner(content_area);

            let error_text = Paragraph::new("Invalid state: FileDialog mode without active dialog.")
                .style(Style::default().fg(Color::Red));
            f.render_widget(error_block, content_area);
            f.render_widget(error_text, inner_area);
        }
    }
}

// Render editing mode
fn render_editing_mode(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &mut App) {
    let editor_block = Block::default().borders(Borders::ALL).title("Editor");
    let editor_area = editor_block.inner(area);

    // Ensure scroll offset doesn't go beyond limits
    if app.buffer.scroll_offset >= app.buffer.lines.len() && app.buffer.lines.len() > 0 {
        app.buffer.scroll_offset = app.buffer.lines.len() - 1;
    }

    let visible_height = editor_area.height as usize;
    let display_lines = app.buffer.get_display_lines(visible_height);

    // Create TUI text from lines
    let text: Vec<Line> = display_lines.into_iter().map(Line::from).collect();

    let input = Paragraph::new(text)
        .style(Style::default().fg(Color::White));

    f.render_widget(editor_block, area);
    f.render_widget(input, editor_area);

    // Calculate cursor position within the rendered area, accounting for line numbers and scroll
    let line_num_width = if app.buffer.line_numbers {
        app.buffer.lines.len().to_string().len() + 3 // Width + space + │ + space
    } else {
        0
    };

    // Ensure cursor row is within visible bounds relative to scroll
    if app.buffer.cursor_row >= app.buffer.scroll_offset &&
       app.buffer.cursor_row < app.buffer.scroll_offset + visible_height {
        let cursor_y = editor_area.y + (app.buffer.cursor_row - app.buffer.scroll_offset) as u16;
        let cursor_x = editor_area.x + app.buffer.cursor_col as u16 + line_num_width as u16;

        // Clamp cursor X to visible width
        let clamped_cursor_x = cursor_x.min(editor_area.x + editor_area.width.saturating_sub(1));

        f.set_cursor(clamped_cursor_x, cursor_y);
    }
}

// Render viewing mode
fn render_viewing_mode(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let history_block = Block::default().borders(Borders::ALL).title("Document History (Read-Only)");
    let history_area = history_block.inner(area);

    let history_items_str = app.document.get_leaf_history(); // Get formatted strings

    // Create ListItems from strings
    let items: Vec<ListItem> = history_items_str.iter()
        .map(|h_str| ListItem::new(h_str.as_str()))
        .collect();

    // Create the list widget
    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("> "); // Indicator for selected item

    // Create state for the list to handle scrolling/selection
    let mut list_state = tui::widgets::ListState::default();
    
    // Ensure scroll offset maps correctly to list selection/offset
    if !app.document.leaves.is_empty() {
        // Clamp scroll to valid range
        let max_scroll = app.document.leaves.len().saturating_sub(1);
        let valid_scroll = app.history_scroll.min(max_scroll);
        
        list_state.select(Some(valid_scroll)); // Select the item corresponding to scroll offset
    }

    f.render_widget(history_block, area);
    f.render_stateful_widget(list, history_area, &mut list_state);
}

// Render tree view mode
fn render_tree_view_mode(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let tree_block = Block::default().borders(Borders::ALL).title("Merkle Tree Structure");
    let tree_area = tree_block.inner(area);
    
    let tree_items_str = app.document.get_tree_structure(); // Get formatted tree structure
    
    // Create ListItems from strings
    let items: Vec<ListItem> = tree_items_str.iter()
        .map(|t_str| ListItem::new(t_str.as_str()))
        .collect();
        
    // Create the list widget
    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().bg(Color::DarkGray)) // Less prominent highlight
        .highlight_symbol("→ "); // Indicator for current line
        
    // Create state for scrolling
    let mut list_state = tui::widgets::ListState::default();
    
    // Clamp scroll to valid range
    let max_scroll = tree_items_str.len().saturating_sub(1);
    let valid_scroll = app.history_scroll.min(max_scroll);
    
    list_state.select(Some(valid_scroll)); // Use select to control view offset
    
    f.render_widget(tree_block, area);
    f.render_stateful_widget(list, tree_area, &mut list_state);
}

// Render verification detail mode
fn render_verify_detail_mode(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let verify_block = Block::default().borders(Borders::ALL).title("Verification Details");
    let verify_area = verify_block.inner(area);
    f.render_widget(verify_block, area); // Render block first

    let mut items: Vec<ListItem> = Vec::new(); // Initialize list items vector

    // --- Add Overall Status ---
    if let Some(v) = &app.document.last_verification {
        let (status_text, status_style) = if v.valid {
            ("PASSED", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            ("FAILED", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        };
        
        let overall_summary = format!("Overall Status: {} ({:?})", status_text, v.level);
        items.push(ListItem::new(Line::from(Span::styled(overall_summary, status_style))));
        items.push(ListItem::new("-----------------------------------")); // Separator
        
        // --- Add Individual Details ---
        for detail in v.details.iter() {
            let style = if detail.valid {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            
            let icon = if detail.valid { " ✓" } else { " ✗" }; // Space for alignment
            items.push(ListItem::new(Span::styled(format!("{} {}", icon, detail.description), style)));
        }
    } else {
        items.push(ListItem::new("Overall Status: Not Yet Verified"));
        items.push(ListItem::new("-----------------------------------")); // Separator
        items.push(ListItem::new("Run verification with Ctrl+V to see details"));
    }

    // --- Render the List ---
    let list = List::new(items) // Use the combined items list
        .style(Style::default().fg(Color::White))
        // Highlight the entire line for simplicity when scrolling
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("→ "); // Indicator for current line

    // Create state for scrolling
    let mut list_state = tui::widgets::ListState::default();
    
    // Calculate total items for scroll clamping
    let total_items = if let Some(v) = &app.document.last_verification { 
        v.details.len() + 2  // +2 for summary lines
    } else { 
        3  // Header + separator + info message
    };
    
    // Clamp scroll to valid range
    let max_scroll = total_items.saturating_sub(1);
    let valid_scroll = app.history_scroll.min(max_scroll);
    
    list_state.select(Some(valid_scroll));

    f.render_stateful_widget(list, verify_area, &mut list_state);
}

// Render metadata editor
fn render_metadata_editor(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &mut App) {
    if let Some(editor) = &app.metadata_editor {
        let block = Block::default().borders(Borders::ALL).title("Edit Metadata");
        let inner_area = block.inner(area);
        f.render_widget(block, area);

        let fields = ["Title:", "Author:", "Keywords:", "Description:"];
        let values = [
            &editor.metadata.title,
            &editor.metadata.author,
            &editor.metadata.keywords.join(", "), // Show as comma-separated
            &editor.metadata.description,
        ];

        let mut items: Vec<ListItem> = Vec::new();
        let mut cursor_pos: Option<(u16, u16)> = None;

        for i in 0..fields.len() {
            let is_selected = i == editor.current_field;
            let is_editing = is_selected && editor.editing;

            let field_style = if is_selected && !is_editing {
                Style::default().bg(Color::Blue).fg(Color::White) // Selected field highlight
            } else {
                Style::default().fg(Color::White)
            };

            let value_style = if is_editing {
                Style::default().fg(Color::Yellow) // Editing value highlight
            } else {
                field_style // Inherit field style if not editing value
            };

            let value_text = if is_editing {
                &editor.edit_buffer
            } else {
                values[i] // We've already pre-computed the joined string in values
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!("{:<12}", fields[i]), field_style), // Pad field name
                Span::styled(value_text, value_style),
            ])));

            // Set cursor position if this field is being edited
            if is_editing {
                cursor_pos = Some((
                    inner_area.x + 12 + editor.edit_buffer.len() as u16, // 12 = field width + space
                    inner_area.y + i as u16, // Y position based on field index
                ));
            }
        }

        // Add instructions
        items.push(ListItem::new("")); // Spacer
        items.push(ListItem::new(Line::from(Span::styled(
            "Arrows: Navigate | Enter: Edit/Save Field | Ctrl+S: Save All | Esc: Cancel Edit/Dialog", 
            Style::default().fg(Color::DarkGray)
        ))));

        let list = List::new(items);
        f.render_widget(list, inner_area);

        // Set cursor if editing
        if let Some((x, y)) = cursor_pos {
            f.set_cursor(x.min(inner_area.right() - 1), y); // Clamp cursor X
        }
    }
}

// Render help screen
fn render_help_screen(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title("Help - BitQuill Merkle Edition");
    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let help_text = app.get_help_text();
    let items: Vec<ListItem> = help_text.iter()
        .map(|line| ListItem::new(line.as_str()))
        .collect();

    // Basic list display, scrolling not implemented yet for help
    let list = List::new(items).style(Style::default().fg(Color::White));
    f.render_widget(list, inner_area);
}

// Render file browser dialog
fn render_file_dialog(
    f: &mut Frame<CrosstermBackend<io::Stdout>>, 
    area: Rect, 
    app: &App, 
    title: &str, 
    show_filename_input: bool
) {
    let dialog_block = Block::default().borders(Borders::ALL).title(title);
    let inner_area = dialog_block.inner(area); // Area inside borders

    // Define constraints based on whether filename input is shown
    let constraints = if show_filename_input {
        vec![
            Constraint::Length(1),  // Current directory path
            Constraint::Min(0),     // File list (takes remaining space)
            Constraint::Length(1),  // Filename input line
            Constraint::Length(1),  // Hint line
        ]
    } else {
        vec![
            Constraint::Length(1),  // Current directory path
            Constraint::Min(0),     // File list
            Constraint::Length(1),  // Hint line
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner_area); // Split the inner area

    f.render_widget(dialog_block, area); // Render the block frame first

    // 1. Current Directory
    let current_dir_text = Paragraph::new(app.file_browser.current_dir.to_string_lossy().to_string())
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(current_dir_text, chunks[0]);

    // 2. File List
    let entries = app.file_browser.get_entries_for_display();
    let items: Vec<ListItem> = entries.iter()
        .map(|entry_str| ListItem::new(entry_str.as_str()))
        .collect();

    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("> ");

    let mut list_state = tui::widgets::ListState::default();
    if !app.file_browser.entries.is_empty() {
        // Clamp selection to valid range
        let clamped_selection = app.file_browser.selected_idx.min(app.file_browser.entries.len() - 1);
        list_state.select(Some(clamped_selection));
    }

    f.render_stateful_widget(list, chunks[1], &mut list_state);

    // 3. Filename Input (Optional)
    let hint_index = if show_filename_input {
        let filename_style = if app.file_browser.is_editing_filename {
            Style::default().fg(Color::Yellow) // Highlight if editing
        } else {
            Style::default().fg(Color::White)
        };
        
        let filename_text = format!("Filename: {}", app.file_browser.filename_input);
        let filename_para = Paragraph::new(filename_text).style(filename_style);
        f.render_widget(filename_para, chunks[2]);

        // Show cursor if editing filename
        if app.file_browser.is_editing_filename {
            f.set_cursor(
                chunks[2].x + 10 + app.file_browser.filename_input.len() as u16, // "Filename: ".len() = 10
                chunks[2].y
            );
        }
        3 // Hint is at index 3
    } else {
        2 // Hint is at index 2
    };

    // 4. Hint Text
    let hint_text_str = if show_filename_input {
        "Arrows: Navigate | Enter: Confirm/Select | F/Tab: Edit Filename | Esc: Cancel"
    } else {
        "Arrows: Navigate | Enter: Confirm/Select | Esc: Cancel"
    };
    
    let hint = Paragraph::new(hint_text_str).style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, chunks[hint_index]);
}

// Render unsaved changes dialog
fn render_unsaved_dialog(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    if let Dialog::UnsavedChanges(action) = &app.dialog {
        let action_desc = match action {
            UnsavedAction::New => "create a new document",
            UnsavedAction::Open => "open another document",
            UnsavedAction::Quit => "quit",
            UnsavedAction::OpenRecent(_) => "open a recent file",
        };
        
        let text = vec![
            Line::from(Span::styled("Unsaved Changes", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(format!("The current document has unsaved changes.")),
            Line::from(format!("Do you want to save before you {}?", action_desc)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  [Y]", Style::default().fg(Color::Green)), Span::raw("es (Save) "),
                Span::styled("  [N]", Style::default().fg(Color::Red)), Span::raw("o (Discard) "),
                Span::styled("  [Esc]", Style::default().fg(Color::Gray)), Span::raw(" Cancel"),
            ]),
        ];

        let paragraph = Paragraph::new(text)
            .alignment(tui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Confirm"));

        // Create a smaller centered rect for the dialog
        let dialog_area = utils::centered_rect(60, 30, area); // 60% width, 30% height

        f.render_widget(paragraph, dialog_area);
    }
}

// Render search/replace UI
fn render_search_ui(f: &mut Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    // Create a centered dialog for search/replace
    let dialog_area = utils::centered_rect(70, 20, area); // 70% width, 20% height
    
    let title = if app.search_state.is_replace_mode {
        "Search & Replace"
    } else {
        "Search"
    };
    
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner_area = block.inner(dialog_area);
    
    // Define layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(1), // Search query input
                Constraint::Length(1), // Replace text input (if in replace mode)
                Constraint::Length(1), // Status/count line
                Constraint::Length(1), // Hints line
            ]
            .as_ref(),
        )
        .split(inner_area);
    
    // Render the main dialog border
    f.render_widget(block, dialog_area);
    
    // 1. Search query input
    let search_style = Style::default().fg(Color::Yellow);
    let search_text = format!("Search: {}", app.search_state.search_query);
    let search_input = Paragraph::new(search_text).style(search_style);
    f.render_widget(search_input, chunks[0]);
    
    // 2. Replace text input (only in replace mode)
    if app.search_state.is_replace_mode {
        let replace_style = if app.search_state.search_query.is_empty() {
            Style::default().fg(Color::DarkGray) // Dim when not active
        } else {
            Style::default().fg(Color::Yellow)
        };
        
        let replace_text = format!("Replace: {}", app.search_state.replace_text);
        let replace_input = Paragraph::new(replace_text).style(replace_style);
        f.render_widget(replace_input, chunks[1]);
    }
    
    // 3. Status/count line
    let status_text = if !app.search_state.current_matches.is_empty() {
        let current = app.search_state.current_match_idx.unwrap_or(0) + 1;
        let total = app.search_state.current_matches.len();
        format!("Match {}/{} - Case sensitive: {}", 
                current, total, 
                if app.search_state.case_sensitive { "Yes" } else { "No" })
    } else if !app.search_state.search_query.is_empty() {
        "No matches found".to_string()
    } else {
        "Enter search term and press Enter".to_string()
    };
    
    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::White));
    f.render_widget(status, chunks[2]);
    
    // 4. Hints line
    let hints = if app.search_state.is_replace_mode {
        "Enter: Search/Confirm | Esc: Cancel | Ctrl+N: Next | Ctrl+P: Prev | Ctrl+R: Replace | Ctrl+A: Replace All | F5: Toggle Case"
    } else {
        "Enter: Search/Confirm | Esc: Cancel | Ctrl+N: Next | Ctrl+P: Prev | F5: Toggle Case"
    };
    
    let hints_para = Paragraph::new(hints)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hints_para, chunks[3]);
    
    // Set cursor position
    if app.search_state.is_replace_mode && !app.search_state.search_query.is_empty() {
        // Editing replace text
        f.set_cursor(
            chunks[1].x + 9 + app.search_state.replace_text.len() as u16, // "Replace: " = 9 chars
            chunks[1].y,
        );
    } else {
        // Editing search query
        f.set_cursor(
            chunks[0].x + 8 + app.search_state.search_query.len() as u16, // "Search: " = 8 chars
            chunks[0].y,
        );
    }
    
    // Also render editor content behind the dialog (dimmed)
    let editor_block = Block::default().borders(Borders::ALL).title("Editor");
    let editor_area = editor_block.inner(area);
    let visible_height = editor_area.height as usize;
    let display_lines = app.buffer.get_display_lines(visible_height);
    let text: Vec<Line> = display_lines.into_iter().map(Line::from).collect();
    let input = Paragraph::new(text)
        .style(Style::default().fg(Color::DarkGray)); // Dimmed text while searching
    
    f.render_widget(editor_block, area);
    f.render_widget(input, editor_area);
}
