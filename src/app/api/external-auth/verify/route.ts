import { NextRequest, NextResponse } from 'next/server';
import { parse } from 'cookie';
import fetch from 'node-fetch';

import { getServerDB } from '@/database/core/db-adaptor';
import { SessionModel } from '@/database/models/session';
import { users } from '@/database/schemas';
import { eq } from 'drizzle-orm';

/**
 * External cookie verification endpoint (default implementation)
 * - Reads cookie from request headers (name from EXTERNAL_AUTH_COOKIE_NAME)
 * - Calls EXTERNAL_AUTH_URL with { cookie } to validate
 * - If valid, looks up local user by email (returned by third-party)
 * - If a local user exists, creates a local agent session for that user
 *
 * Environment variables:
 * - EXTERNAL_AUTH_URL (required) : third-party validation endpoint
 * - EXTERNAL_AUTH_COOKIE_NAME (optional, default: external_auth_cookie)
 * - EXTERNAL_AUTH_API_KEY (optional) : Authorization Bearer for third-party
 */

export async function POST(req: NextRequest) {
  try {
    const cookieHeader = req.headers.get('cookie') || '';
    const cookies = cookieHeader ? parse(cookieHeader) : {};

    const cookieName = process.env.EXTERNAL_AUTH_COOKIE_NAME || 'external_auth_cookie';
    const cookieValue = cookies[cookieName];

    if (!cookieValue) {
      return NextResponse.json({ ok: false, error: 'cookie_missing' }, { status: 401 });
    }

    const validateUrl = process.env.EXTERNAL_AUTH_URL;
    if (!validateUrl) {
      return NextResponse.json({ ok: false, error: 'server_misconfigured' }, { status: 500 });
    }

    // Call third-party validation API (default: POST { cookie })
    const thirdPartyResp = await fetch(validateUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.EXTERNAL_AUTH_API_KEY
          ? { Authorization: `Bearer ${process.env.EXTERNAL_AUTH_API_KEY}` }
          : {}),
      },
      body: JSON.stringify({ cookie: cookieValue }),
    });

    if (!thirdPartyResp.ok) {
      return NextResponse.json({ ok: false, error: 'external_invalid', status: thirdPartyResp.status }, { status: 401 });
    }

    const data = (await thirdPartyResp.json()) as {
      valid?: boolean;
      externalUserId?: string;
      email?: string;
      [k: string]: any;
    };

    if (!data || !data.valid) {
      return NextResponse.json({ ok: false, error: 'invalid_cookie' }, { status: 401 });
    }

    const db = await getServerDB();

    // Try to map to local user by email (default mapping). Do NOT auto-create users in default implementation.
    const email = data.email;
    if (!email) {
      return NextResponse.json({ ok: false, error: 'no_email_returned' }, { status: 400 });
    }

    const found = await db.query.users.findFirst({ where: eq(users.email, email) });

    if (!found) {
      return NextResponse.json({ ok: false, error: 'no_local_user' }, { status: 403 });
    }

    const localUserId = found.id;

    // Create a local agent session for the user
    const sessionModel = new SessionModel(db, localUserId);

    const created = await sessionModel.create({
      type: 'agent',
      config: {},
      session: {
        title: 'External-authenticated session',
      },
    });

    return NextResponse.json({ ok: true, sessionId: created.id, userId: localUserId });
  } catch (error) {
    console.error('[external-auth] verify error:', error);
    return NextResponse.json({ ok: false, error: 'internal_error' }, { status: 500 });
  }
}
