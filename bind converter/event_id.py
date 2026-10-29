from __future__ import annotations

import hashlib
from typing import Optional


class EventIDGenerator:

    @staticmethod
    def generate_event_id(
        timestamp: Optional[str],
        client_ip: Optional[str],
        domain: Optional[str],
        query_type: Optional[str],
        client_port: Optional[str]
    ) -> str:

        # Use empty strings for None values
        components = [
            str(timestamp or ''),
            str(client_ip or ''),
            str(domain or '').lower(),
            str(query_type or ''),
            str(client_port or '')
        ]
        
        # Join components with separator
        event_string = '|'.join(components)
        
        # Generate SHA-256 hash
        event_hash = hashlib.sha256(event_string.encode('utf-8'))
        
        return event_hash.hexdigest()
    
    @staticmethod
    def generate_from_dict(event_data: dict) -> str:

        return EventIDGenerator.generate_event_id(
            timestamp=event_data.get('timestamp'),
            client_ip=event_data.get('client_ip'),
            domain=event_data.get('domain'),
            query_type=event_data.get('query_type'),
            client_port=event_data.get('client_port')
        )