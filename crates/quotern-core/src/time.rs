use jiff::{Timestamp, tz::TimeZone};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DayBounds {
    pub start_ms: i64,
    pub end_ms: i64,
}

pub fn local_day_bounds(now_ms: i64, time_zone: &str) -> Result<DayBounds, jiff::Error> {
    let instant = Timestamp::from_millisecond(now_ms)?;
    let zone = TimeZone::get(time_zone)?;
    let local_now = instant.to_zoned(zone);
    let start = local_now.start_of_day()?;
    let end = start.tomorrow()?;
    Ok(DayBounds {
        start_ms: start.timestamp().as_millisecond(),
        end_ms: end.timestamp().as_millisecond(),
    })
}

#[cfg(test)]
mod tests {
    use super::local_day_bounds;

    #[test]
    fn riga_dst_days_have_local_midnight_bounds() {
        let spring =
            local_day_bounds(1_774_782_000_000, "Europe/Riga").expect("valid test instant");
        let fall = local_day_bounds(1_792_920_000_000, "Europe/Riga").expect("valid test instant");
        assert_eq!(spring.end_ms - spring.start_ms, 23 * 60 * 60 * 1_000);
        assert_eq!(fall.end_ms - fall.start_ms, 25 * 60 * 60 * 1_000);
    }
}
