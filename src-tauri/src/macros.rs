//! 日志宏（需在所有模块之前通过 `#[macro_use]` 引入）

macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_DEBUG, module_path!(), format!($($arg)*)) };
}

macro_rules! log_info {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_INFO, module_path!(), format!($($arg)*)) };
}

macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_WARN, module_path!(), format!($($arg)*)) };
}

macro_rules! log_error {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_ERROR, module_path!(), format!($($arg)*)) };
}
