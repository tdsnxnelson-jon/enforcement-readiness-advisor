#!/usr/bin/env python3
from data_collection.api_client import CBApiClient

c = CBApiClient('https://192.168.1.201:4434/', '9960C6B4-C174-446F-B81A-F36892BC824D', False)
pubs = c.get('/api/bit9platform/v1/publisher', {'rows': 111})
print('Total publishers:', len(pubs))

reputations = {}
for p in pubs:
    rep = p.get('publisherReputation', 'UNKNOWN')
    reputations[rep] = reputations.get(rep, 0) + 1

print('Reputation distribution:', reputations)
print()
print('Sample publishers:')
for p in pubs[:10]:
    print(f"  {p['name'][:35]:35} | rep={p.get('publisherReputation', 'UNKNOWN'):20} | state={p.get('publisherState', 'UNKNOWN')}")
