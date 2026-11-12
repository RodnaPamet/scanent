// A stand-in MCP server for step 11 of deploy/smoke.sh. It is run from the
// scanent image itself (the image's Node, no dependency), on the egress
// proxy's outer network, behind a certificate the step makes.
//
// It speaks the three messages the scanner declares (`initialize`, the
// `notifications/initialized` notification, `tools/list`) over Streamable
// HTTP, and refuses every other one. Each message's method is printed on its
// own line, so the step can assert that nothing else was ever asked of it.
//
//   SMOKE_MCP_CERT, SMOKE_MCP_KEY   the certificate and its key, PEM files
//
// It is a test fixture: it serves two fixed tools and reads nothing.
'use strict';

const fs = require('node:fs');
const { Buffer } = require('node:buffer');
const https = require('node:https');

const TOOLS = [
    {
        name: 'smoke_lookup_ticket',
        description: 'Look a ticket up by its id.',
        inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
        annotations: { readOnlyHint: true },
    },
    {
        name: 'smoke_close_ticket',
        description: 'Close a ticket.',
        inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
    },
];

const MAX_BODY_BYTES = 64 * 1024;

function send(res, status, payload) {
    if (payload === undefined) {
        res.writeHead(status).end();
        return;
    }
    const body = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }).end(body);
}

const server = https.createServer(
    { cert: fs.readFileSync(process.env.SMOKE_MCP_CERT), key: fs.readFileSync(process.env.SMOKE_MCP_KEY) },
    (req, res) => {
        if (req.method !== 'POST' || req.url !== '/mcp') {
            console.log(`refused ${req.method} ${req.url}`);
            send(res, 404, { error: 'not found' });
            return;
        }
        const chunks = [];
        let bytes = 0;
        req.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > MAX_BODY_BYTES) req.destroy();
            else chunks.push(chunk);
        });
        req.on('end', () => {
            let message;
            try {
                message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch {
                console.log('refused unparseable');
                send(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
                return;
            }
            const method = typeof message.method === 'string' ? message.method : '';
            console.log(`message ${method}`);
            if (method === 'initialize') {
                send(res, 200, {
                    jsonrpc: '2.0',
                    id: message.id,
                    result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'scanent-smoke', version: '1' } },
                });
            } else if (method === 'notifications/initialized') {
                send(res, 202);
            } else if (method === 'tools/list') {
                send(res, 200, { jsonrpc: '2.0', id: message.id, result: { tools: TOOLS } });
            } else {
                send(res, 200, { jsonrpc: '2.0', id: message.id ?? null, error: { code: -32601, message: 'Method not found' } });
            }
        });
    },
);

for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => process.exit(0));
server.listen(443, () => console.log('listening 443'));
