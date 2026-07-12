pub fn current_cpu_micros() -> Option<u64> {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return None;
    }

    let user = (usage.ru_utime.tv_sec as i128)
        .saturating_mul(1_000_000)
        .saturating_add(usage.ru_utime.tv_usec as i128);
    let sys = (usage.ru_stime.tv_sec as i128)
        .saturating_mul(1_000_000)
        .saturating_add(usage.ru_stime.tv_usec as i128);

    if user < 0 || sys < 0 {
        return None;
    }
    Some((user + sys) as u64)
}

pub fn current_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return None;
        }
        Some(resident_pages * (page_size as u64) / 1024)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if rc != 0 {
            return None;
        }
        #[cfg(target_os = "macos")]
        {
            Some((usage.ru_maxrss as u64) / 1024)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(usage.ru_maxrss as u64)
        }
    }
}

pub fn cpu_pct(cpu_before: Option<u64>, cpu_after: Option<u64>, wall_ns: u128) -> f64 {
    let Some(before) = cpu_before else {
        return 0.0;
    };
    let Some(after) = cpu_after else {
        return 0.0;
    };
    if after <= before || wall_ns == 0 {
        return 0.0;
    }
    let cpu_used_us = after.saturating_sub(before);
    let wall_us = (wall_ns / 1_000).max(1) as f64;
    ((cpu_used_us as f64) / wall_us) * 100.0
}

pub fn percentile_from_sorted(values: &[u128], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    let index = ((values.len().saturating_sub(1) as f64) * q).round() as usize;
    values[index] as f64
}
