from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple


class TimestampUtils:

    # BIND9 timestamp format: 06-Jul-2026 14:22:11.431
    BIND9_TIMESTAMP_PATTERN = re.compile(
        r'(\d{2})-([A-Z][a-z]{2})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})'
    )
    
    MONTH_MAP = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    @staticmethod
    def parse_bind9_timestamp(timestamp_str: Optional[str]) -> Optional[datetime]:

        if not timestamp_str:
            return None
        
        match = TimestampUtils.BIND9_TIMESTAMP_PATTERN.match(timestamp_str)
        if not match:
            return None
        
        try:
            day = int(match.group(1))
            month_str = match.group(2)
            year = int(match.group(3))
            hour = int(match.group(4))
            minute = int(match.group(5))
            second = int(match.group(6))
            millisecond = int(match.group(7))
            
            month = TimestampUtils.MONTH_MAP.get(month_str)
            if month is None:
                return None
            
            return datetime(
                year, month, day,
                hour, minute, second,
                millisecond * 1000,  # Convert to microseconds
                tzinfo=timezone.utc
            )
        except (ValueError, IndexError):
            return None
    
    @staticmethod
    def normalize_timestamp(
        timestamp_str: Optional[str],
        default_timezone: str = 'UTC'
    ) -> Dict[str, Optional[str]]:
        result = {
            'timestamp': None,
            'timestamp_iso8601': None,
            'timestamp_unix': None,
            'date': None,
            'time': None,
            'year': None,
            'month': None,
            'day': None,
            'hour': None,
            'minute': None,
            'second': None,
            'millisecond': None,
            'weekday': None,
            'week_number': None,
            'day_of_year': None,
            'is_weekend': None,
            'timezone': default_timezone
        }
        
        if not timestamp_str:
            return result
        
        dt = TimestampUtils.parse_bind9_timestamp(timestamp_str)
        if dt is None:
            return result
        
        # ISO 8601 format
        result['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        result['timestamp_iso8601'] = result['timestamp']
        
        # Unix timestamp (seconds since epoch)
        result['timestamp_unix'] = str(int(dt.timestamp()))
        
        # Date and time components
        result['date'] = dt.strftime('%Y-%m-%d')
        result['time'] = dt.strftime('%H:%M:%S.%f')[:-3]
        
        # Individual components
        result['year'] = str(dt.year)
        result['month'] = f"{dt.month:02d}"
        result['day'] = f"{dt.day:02d}"
        result['hour'] = f"{dt.hour:02d}"
        result['minute'] = f"{dt.minute:02d}"
        result['second'] = f"{dt.second:02d}"
        result['millisecond'] = f"{dt.microsecond // 1000:03d}"
        
        # Week-related information
        weekday_num = dt.weekday()  # Monday = 0, Sunday = 6
        weekday_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        result['weekday'] = weekday_names[weekday_num]
        result['week_number'] = f"{dt.isocalendar()[1]:02d}"
        result['day_of_year'] = str(dt.timetuple().tm_yday)
        
        # Weekend check (Saturday = 5, Sunday = 6)
        result['is_weekend'] = 'true' if weekday_num >= 5 else 'false'
        
        result['timezone'] = default_timezone
        
        return result
    
    @staticmethod
    def get_current_timestamp() -> Dict[str, Optional[str]]:
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime('%d-%b-%Y %H:%M:%S.') + f"{now.microsecond // 1000:03d}"
        return TimestampUtils.normalize_timestamp(timestamp_str)
        