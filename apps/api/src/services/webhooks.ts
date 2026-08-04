import crypto from 'node:crypto';
import { db } from '../db/index.js';

export interface WebhookPayload {
  event: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export class WebhookService {
  static listSubscriptions(orgId: string) {
    return (db.prepare('SELECT * FROM webhook_subscriptions WHERE org_id = ?').all(orgId) as any[]).map((row) => ({
      id: row.id,
      org_id: row.org_id,
      url: row.url,
      events: JSON.parse(row.events || '["cert_revoked"]'),
      created_at: row.created_at,
      active: row.active === true || row.active === 1,
    }));
  }

  static createSubscription(orgId: string, url: string, events: string[] = ['cert_revoked']) {
    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString('hex');
    const now = new Date().toISOString();

    db.prepare('INSERT INTO webhook_subscriptions').run(
      id,
      orgId,
      url,
      JSON.stringify(events),
      secret,
      now,
      true
    );

    return { id, org_id: orgId, url, events, secret, created_at: now, active: true };
  }

  static deleteSubscription(id: string, orgId: string): boolean {
    const row = db.prepare('SELECT * FROM webhook_subscriptions WHERE id = ?').get(id) as any;
    if (!row || row.org_id !== orgId) {
      return false;
    }
    db.prepare('DELETE FROM webhook_subscriptions WHERE id = ?').run(id);
    return true;
  }

  static async fanOut(event: string, orgId: string, data: Record<string, unknown>): Promise<void> {
    const subscriptions = (db.prepare('SELECT * FROM webhook_subscriptions WHERE org_id = ?').all(orgId) as any[]).filter(
      (sub) => (sub.active === true || sub.active === 1) && JSON.parse(sub.events || '[]').includes(event)
    );

    const payload: WebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      data,
    };

    await Promise.allSettled(
      subscriptions.map(async (sub) => {
        const body = JSON.stringify(payload);
        const signature = crypto.createHmac('sha256', sub.secret).update(body).digest('hex');
        let lastError: string | null = null;
        let responseStatus: number | null = null;
        let attempt = 0;
        for (attempt = 1; attempt <= 3; attempt++) {
          try {
            const response = await fetch(sub.url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-Warden-Event': event, 'X-Warden-Signature': signature },
              body,
              signal: AbortSignal.timeout(5000),
            });
            responseStatus = response.status;
            if (response.ok) break;
            lastError = `Webhook delivery failed (${response.status})`;
          } catch (error) {
            lastError = (error as Error).message;
          }
          if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, attempt * 100));
        }
        const delivered = responseStatus !== null && responseStatus >= 200 && responseStatus < 300;
        db.prepare('INSERT INTO webhook_deliveries').run(
          crypto.randomUUID(), sub.id, event, delivered ? 'delivered' : 'failed', attempt,
          responseStatus, delivered ? null : lastError, new Date().toISOString()
        );
        if (!delivered) throw new Error(lastError || `Webhook delivery failed for ${sub.url}`);
      })
    );
  }

  static listDeliveries(subscriptionId: string, orgId: string) {
    const subscription = db.prepare('SELECT * FROM webhook_subscriptions WHERE id = ?').get(subscriptionId) as any;
    if (!subscription || subscription.org_id !== orgId) return null;
    return db.prepare('SELECT * FROM webhook_deliveries WHERE subscription_id = ?').all(subscriptionId);
  }
}
