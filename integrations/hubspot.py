# slack.py

import json
import secrets
import asyncio
import base64
import httpx
import requests
from urllib.parse import quote
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis
from integrations.integration_item import IntegrationItem

CLIENT_ID = 'ebc099b6-8f6d-4d22-92e7-129b399cc840'
CLIENT_SECRET = 'd3be2ed7-4154-4c15-bdc2-cc1fe497d19c'
REDIRECT_URI = 'https://integrationbackend-ff4r.onrender.com/integrations/hubspot/oauth2callback'
SCOPE = 'crm.objects.contacts.read'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)

    return f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={quote(REDIRECT_URI)}&scope={SCOPE}&state={encoded_state}'


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))

    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode())

    user_id = state_data['user_id']
    org_id = state_data['org_id']
    original_state = state_data['state']

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    if not saved_state or json.loads(saved_state)['state'] != original_state:
        raise HTTPException(status_code=400, detail='State mismatch')

    await delete_key_redis(f'hubspot_state:{org_id}:{user_id}')

    async with httpx.AsyncClient() as client:
        token_response = await client.post('https://api.hubapi.com/oauth/v1/token', data={
            'grant_type': 'authorization_code',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': REDIRECT_URI,
            'code': code
        }, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(token_response.json()), expire=600)

    return HTMLResponse(content="""
    <html>
        <script>window.close();</script>
    </html>
    """)


async def get_hubspot_credentials(user_id, org_id):
    creds = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not creds:
        raise HTTPException(status_code=400, detail="No credentials found")
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')
    return json.loads(creds)


async def create_integration_item_metadata_object(contact):
    return IntegrationItem(
        id=contact.get('id'),
        type='Contact',
        name=contact.get('properties', {}).get('firstname', 'Unnamed'),
        creation_time=contact.get('createdAt'),
        last_modified_time=contact.get('updatedAt'),
        url=f"https://app.hubspot.com/contacts/{contact.get('id')}",
        parent_id=None,
        parent_path_or_name=None,
    )


async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.get(
        'https://api.hubapi.com/crm/v3/objects/contacts',
        headers=headers
    )

    items = []
    if response.status_code == 200:
        for contact in response.json().get('results', []):
            item = await create_integration_item_metadata_object(contact)
            items.append(item.__dict__)

    return items
