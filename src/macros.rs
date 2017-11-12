// Most of our lookups follow the same pattern - macro out the repetition.
macro_rules! ares_call {
    ($ares_call:ident,
     $channel:expr,
     $name:expr,
     $dns_class:expr,
     $query_type:expr,
     $callback:expr,
     $handler:expr) => {
        {
            let c_name = CString::new($name).unwrap();
            let c_arg = Box::into_raw(Box::new($handler));
            unsafe {
                c_ares_sys::$ares_call(
                    $channel,
                    c_name.as_ptr(),
                    $dns_class as c_int,
                    $query_type as c_int,
                    Some($callback),
                    c_arg as *mut c_void,
                );
            }
            panic::propagate();
        }
    }
}

macro_rules! ares_query {
    ($($arg:tt)*) => { ares_call!(ares_query, $($arg)*) }
}

macro_rules! ares_search {
    ($($arg:tt)*) => { ares_call!(ares_search, $($arg)*) }
}

// Most of our `ares_callback` implementations are much the same - macro out
// the repetition.
macro_rules! ares_callback {
    ($arg:expr, $status:expr, $abuf:expr, $alen:expr, $parser:expr) => {
        {
            panic::catch(|| {
                let result = if $status == c_ares_sys::ARES_SUCCESS {
                    let data = slice::from_raw_parts($abuf, $alen as usize);
                    $parser(data)
                } else {
                    Err(Error::from($status))
                };
                let handler = Box::from_raw($arg);
                handler(result);
            });
        }
    }
}
