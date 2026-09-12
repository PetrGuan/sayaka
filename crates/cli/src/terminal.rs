// SPDX-License-Identifier: MPL-2.0

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    execute, queue,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Normal,
    Header,
    Muted,
    Selected,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    pub style: Style,
}

pub struct Signals {
    interrupt: Arc<AtomicBool>,
    terminate: Arc<AtomicBool>,
    #[cfg(unix)]
    registrations: Vec<signal_hook::SigId>,
}

impl Signals {
    pub fn new() -> io::Result<Self> {
        let result = Self {
            interrupt: Arc::new(AtomicBool::new(false)),
            terminate: Arc::new(AtomicBool::new(false)),
            #[cfg(unix)]
            registrations: Vec::new(),
        };
        #[cfg(unix)]
        let result = {
            let mut result = result;
            result.registrations.push(signal_hook::flag::register(
                signal_hook::consts::SIGINT,
                Arc::clone(&result.interrupt),
            )?);
            result.registrations.push(signal_hook::flag::register(
                signal_hook::consts::SIGTERM,
                Arc::clone(&result.terminate),
            )?);
            result
        };
        Ok(result)
    }
    pub fn exit_code(&self) -> Option<u8> {
        if self.terminate.load(Ordering::Relaxed) {
            Some(143)
        } else if self.interrupt.load(Ordering::Relaxed) {
            Some(130)
        } else {
            None
        }
    }
}

#[cfg(unix)]
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.registrations.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

pub struct Terminal {
    active: bool,
    raw: bool,
    color: bool,
    previous: Vec<Line>,
    size: (u16, u16),
}

impl Terminal {
    pub fn enter() -> io::Result<Self> {
        let mut result = Self {
            active: false,
            raw: false,
            color: std::env::var_os("NO_COLOR").is_none()
                && std::env::var_os("CLICOLOR").is_none_or(|value| value != "0"),
            previous: Vec::new(),
            size: (0, 0),
        };
        terminal::enable_raw_mode()?;
        result.raw = true;
        // Mark active before writing: a partial command sequence also needs cleanup.
        result.active = true;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            Hide,
            Clear(ClearType::All)
        )?;
        Ok(result)
    }
    pub fn invalidate(&mut self) {
        self.previous.clear();
    }
    pub fn draw(&mut self, frame: &[Line], width: u16, height: u16) -> io::Result<()> {
        let mut out = io::stdout().lock();
        self.draw_to(&mut out, frame, width, height)
    }
    fn draw_to(
        &mut self,
        out: &mut impl Write,
        frame: &[Line],
        width: u16,
        height: u16,
    ) -> io::Result<()> {
        if self.size != (width, height) || self.previous.is_empty() {
            queue!(out, Clear(ClearType::All))?;
            self.previous.clear();
            self.size = (width, height);
        }
        for (row, line) in frame.iter().enumerate() {
            if self.previous.get(row) == Some(line) {
                continue;
            }
            queue!(
                out,
                MoveTo(0, u16::try_from(row).map_err(io::Error::other)?),
                ResetColor,
                Clear(ClearType::CurrentLine)
            )?;
            if self.color {
                match line.style {
                    Style::Header => {
                        queue!(out, SetForegroundColor(Color::Cyan))?;
                    }
                    Style::Muted => {
                        queue!(out, SetForegroundColor(Color::DarkGrey))?;
                    }
                    Style::Warning => {
                        queue!(out, SetForegroundColor(Color::Yellow))?;
                    }
                    Style::Selected => {
                        queue!(
                            out,
                            SetForegroundColor(Color::Black),
                            SetBackgroundColor(Color::Cyan)
                        )?;
                    }
                    Style::Normal => {}
                }
            }
            queue!(out, Print(&line.text))?;
        }
        if self.color {
            queue!(out, ResetColor)?;
        }
        out.flush()?;
        self.previous = frame.to_vec();
        Ok(())
    }
    pub fn restore(&mut self) -> io::Result<()> {
        self.restore_with(terminal::disable_raw_mode, || {
            execute!(io::stdout(), ResetColor, Show, LeaveAlternateScreen)
        })
    }
    fn restore_with(
        &mut self,
        mut disable_raw: impl FnMut() -> io::Result<()>,
        mut leave_screen: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let raw = if self.raw {
            match disable_raw() {
                Ok(()) => {
                    self.raw = false;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        let screen = if self.active {
            match leave_screen() {
                Ok(()) => {
                    self.active = false;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        match (raw, screen) {
            (Err(a), Err(b)) => Err(io::Error::other(format!(
                "raw-mode restore failed: {a}; screen restore failed: {b}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("terminal restoration failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct BrokenOutput;
    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected output failure",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_failure_is_not_committed_and_both_restore_paths_are_attempted() {
        let mut terminal = Terminal {
            active: false,
            raw: false,
            color: false,
            previous: Vec::new(),
            size: (0, 0),
        };
        let frame = vec![Line {
            text: "snapshot".into(),
            style: Style::Normal,
        }];
        assert_eq!(
            terminal
                .draw_to(&mut BrokenOutput, &frame, 80, 24)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(terminal.previous.is_empty());
        terminal.raw = true;
        terminal.active = true;
        let raw_called = Cell::new(false);
        let screen_called = Cell::new(false);
        let error = terminal
            .restore_with(
                || {
                    raw_called.set(true);
                    Err(io::Error::other("raw failure"))
                },
                || {
                    screen_called.set(true);
                    Err(io::Error::other("screen failure"))
                },
            )
            .unwrap_err();
        assert!(raw_called.get() && screen_called.get());
        assert!(
            error.to_string().contains("raw failure")
                && error.to_string().contains("screen failure")
        );
        terminal.restore_with(|| Ok(()), || Ok(())).unwrap();
        assert!(!terminal.active && !terminal.raw);
    }
}
