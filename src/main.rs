mod app;
mod constants;
mod error;
mod merkle;
mod utils;
mod vdf;

use app::App;
use error::BitQuillError;


use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{io, thread, time::Duration};
use tui::{backend::CrosstermBackend, Terminal};

fn main() -> Result<(), BitQuillError> {
    // Setup terminal with proper error handling
    enable_raw_mode().map_err(BitQuillError::IoError)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(BitQuillError::IoError)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(BitQuillError::IoError)?;

    // Create app state with proper error handling
    let mut app = match App::new() {
        Ok(app) => app,
        Err(e) => {
            // Attempt to restore terminal before exiting
            let _ = disable_raw_mode(); // Use let _ = to ignore result explicitly
            let _ = execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            );

            eprintln!("Failed to initialize application: {}", e);
            return Err(e); // Propagate the error
        }
    };

    // Set up panic handler to restore terminal state
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Try to restore terminal state
        let _ = disable_raw_mode();
        let mut stdout_panic = io::stdout(); // Create a new handle for panic context
        let _ = execute!(stdout_panic, LeaveAlternateScreen, DisableMouseCapture);

        // Print panic information
        eprintln!("Application panic: {}", panic_info);

        // Call the default handler
        default_hook(panic_info);
    }));

    // --- Main Loop ---
    loop {
        // Draw UI with proper error handling
        if let Err(e) = terminal.draw(|f| app::ui::ui(f, &mut app)) {
            eprintln!("UI rendering error: {}", e);
            // Try to continue despite rendering error
            thread::sleep(Duration::from_millis(100));
        }

        // Update application state (process VDF ticks, check idle, auto-save)
        if let Err(e) = app.update() {
            eprintln!("Application update error: {}", e);
            app.message = format!("Error during update: {}", e);
        }

        // Process events with a timeout to allow for background updates
        match event::poll(Duration::from_millis(100)) {
            Ok(poll_result) => {
                if poll_result {
                    match event::read() {
                        Ok(Event::Key(key)) => {
                            // Process key events with proper error handling
                            if let Err(e) = app::input::process_key_event(&mut app, key) {
                                eprintln!("Error processing key event: {}", e);
                                app.message = format!("Error: {}", e);
                            }
                        }
                        Ok(Event::Resize(..)) => {
                            // Terminal resize - handled by tui-rs automatically
                        }
                        Ok(_) => {
                            // Ignore other events like Mouse events for now
                        }
                        Err(e) => {
                            // Error reading event
                            eprintln!("Error reading event: {}", e);
                            // Brief sleep to prevent tight error loop
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }
            Err(e) => {
                 eprintln!("Error polling events: {}", e);
                 // Error in poll() - brief sleep to prevent tight error loop
                 thread::sleep(Duration::from_millis(100));
            }
        }

        // If quit has been requested, break the loop
        if app.should_quit {
            break;
        }
    }

    // Prepare for shutdown (save recent files, stop VDF clock)
    app.shutdown();

    // Restore terminal state
    disable_raw_mode().map_err(BitQuillError::IoError)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(BitQuillError::IoError)?;
    terminal.show_cursor().map_err(BitQuillError::IoError)?;

    Ok(())
}
