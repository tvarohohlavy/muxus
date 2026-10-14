import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import type { LoginSequence } from '@muxus/shared';
import { TERMINAL_SESSION_CLOSE_REASON } from '@muxus/shared/ws-protocol';
import { registerTerminalSocket } from '../../../server/src/ws/terminal-socket.js';
import { TerminalInputs } from '../../../server/src/ws/terminal-inputs.js';
import { MuxusDatabase } from '../../../server/src/persistence/database.js';
import type { ConnectIo } from '../../../server/src/ssh/connection-manager.js';
import { EarlySecretReads } from '../../../server/src/security/early-secret-reads.js';

class TestSocket extends EventEmitter {
  readonly OPEN = 1;
  readyState = this.OPEN;
  bufferedAmount = 0;
  readonly send = vi.fn();
  readonly ping = vi.fn();

  close(code?: number, reason?: string): void {
    if (this.readyState !== this.OPEN) return;
    this.readyState = 3;
    this.emit('close', code ?? 1005, Buffer.from(reason ?? ''));
  }
}

const enable: LoginSequence = {
  steps: [
    { id: '1', kind: 'wait', pattern: '>', timeoutSeconds: 5 },
    { id: '2', kind: 'send', text: 'enable', enter: true },
  ],
};

/** An SSH shell session on a mocked transport, for the alias `router` in the folder `Core`. */
function sshSession(
  database: MuxusDatabase,
  options: {
    vault?: object;
    /** Settles the shell when called; by default it is ready at once. */
    connectShell?: (shell: unknown, io: ConnectIo) => Promise<unknown>;
  } = {},
) {
  let route!: (socket: TestSocket) => void;
  const stream = Object.assign(new EventEmitter(), {
    close: vi.fn(),
    write: vi.fn(),
    setWindow: vi.fn(),
    pause: vi.fn(),
    resume: vi.fn(),
  });
  const shell = {
    lease: {
      connection: {
        id: 'connection-1',
        host: 'router.example',
        user: 'admin',
        sftpAvailable: false,
        configForwards: [],
        onHealth: () => () => undefined,
        onClose: () => () => undefined,
      },
      release: vi.fn(),
    },
    stream,
    transport: 'new',
    summary: {},
  };
  const connectShell = vi.fn((...args: unknown[]) =>
    options.connectShell ? options.connectShell(shell, args[1] as ConnectIo) : Promise.resolve(shell),
  );
  const app = {
    get: (_path: string, _options: unknown, handler: (socket: TestSocket) => void) => {
      route = handler;
    },
    log: { info: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  };
  const ctx = {
    connections: {
      connectShell,
      resolveProfile: (profile: unknown) => profile,
      metadataAliasFor: (profile: { target: string }) => profile.target,
      leaseCount: () => 0,
    },
    forwards: { startConfig: vi.fn(), stop: vi.fn(), stopSessionForConnection: vi.fn() },
    database,
    history: { append: vi.fn() },
    vault: options.vault ?? { secrets: () => [] },
    terminalInputs: new TerminalInputs(),
  };
  registerTerminalSocket(app as never, ctx as never);

  const socket = new TestSocket();
  route(socket);
  socket.emit(
    'message',
    Buffer.from(
      JSON.stringify({ op: 'connect', profile: { kind: 'ssh', target: 'router' }, cols: 80, rows: 24 }),
    ),
    false,
  );
  const frames = () =>
    socket.send.mock.calls
      .filter(([frame]) => typeof frame === 'string')
      .map(([frame]) => JSON.parse(String(frame)) as { op: string; state?: string; step?: number });
  return { socket, stream, frames, connectShell };
}

describe('login sequences on SSH sessions', () => {
  it('runs the folder sequence of the alias over the shell channel', async () => {
    const database = new MuxusDatabase(':memory:');
    try {
      database.setFolderLoginSequence(database.upsertFolderSettings('Core', {}).id, enable);
      database.updateOpenSshMetadata('router', { group: 'Core' });
      const { socket, stream, frames } = sshSession(database);

      await vi.waitFor(() => expect(frames().some((frame) => frame.op === 'ready')).toBe(true));
      const ops = frames().map((frame) => frame.op);
      expect(ops.indexOf('login-sequence')).toBeLessThan(ops.indexOf('ready'));
      expect(stream.write).not.toHaveBeenCalled();

      stream.emit('data', Buffer.from('\x1b[1mrouter\x1b[0m>'));
      await vi.waitFor(() => expect(stream.write).toHaveBeenCalledWith(Buffer.from('enable\r')));
      await vi.waitFor(() =>
        expect(frames().filter((frame) => frame.op === 'login-sequence').at(-1)).toMatchObject({
          state: 'done',
          step: 2,
        }),
      );
      // Typed input still goes through, and the sequence never types again.
      socket.emit('message', Buffer.from('show run\r'), true);
      stream.emit('data', Buffer.from('router>'));
      await new Promise((resolve) => setImmediate(resolve));
      expect(stream.write.mock.calls.map(([data]) => String(data))).toEqual(['enable\r', 'show run\r']);
      socket.close(1000, TERMINAL_SESSION_CLOSE_REASON);
    } finally {
      database.close();
    }
  });

  it('reads the sequence’s password-manager secret while the connection is made', async () => {
    const database = new MuxusDatabase(':memory:');
    try {
      const folder = database.upsertFolderSettings('Core', {});
      database.setFolderLoginSequence(folder.id, {
        steps: [
          { id: '1', kind: 'wait', pattern: '>', timeoutSeconds: 5 },
          { id: '2', kind: 'send', text: 'enable', enter: true },
          { id: '3', kind: 'secret', secretId: 'enable-secret', enter: true },
        ],
      });
      database.updateOpenSshMetadata('router', { group: 'Core' });
      const order: string[] = [];
      let connected!: () => void;
      const vault = {
        secrets: () => [{ id: 'enable-secret', name: 'Enable' }],
        externalSecret: (id: string) =>
          id === 'enable-secret' ? { name: 'Enable', provider: 'fakevault', providerLabel: 'FakeVault' } : undefined,
        secretValue: vi.fn(() => {
          order.push('read');
          return Promise.resolve('enable-Secret-4711');
        }),
      };
      const { socket, stream, frames, connectShell } = sshSession(database, {
        vault,
        connectShell: (shell) => {
          order.push('connect');
          return new Promise((resolve) => (connected = () => resolve(shell)));
        },
      });

      const connectedSpy = vi.spyOn(EarlySecretReads.prototype, 'connected');
      // Connecting starts first, so each hop's password is read ahead of the sequence's.
      await vi.waitFor(() => expect(order).toEqual(['connect', 'read']));
      expect(connectShell.mock.calls[0]?.[1]).toHaveProperty('earlySecrets');
      // The minute for unused values starts only once the shell is up.
      expect(connectedSpy).not.toHaveBeenCalled();
      connected();
      await vi.waitFor(() => expect(frames().some((frame) => frame.op === 'ready')).toBe(true));
      expect(connectedSpy).toHaveBeenCalledTimes(1);
      connectedSpy.mockRestore();
      stream.emit('data', Buffer.from('router>'));
      await vi.waitFor(() =>
        expect(frames().filter((frame) => frame.op === 'login-sequence').at(-1)).toMatchObject({ state: 'done' }),
      );
      expect(stream.write.mock.calls.map(([data]) => String(data))).toEqual(['enable\r', 'enable-Secret-4711\r']);
      expect(vault.secretValue).toHaveBeenCalledTimes(1);
      socket.close(1000, TERMINAL_SESSION_CLOSE_REASON);
    } finally {
      database.close();
    }
  });

  it('drops what was read early once the sequence ends, or once connected when there is none', async () => {
    for (const withSequence of [false, true]) {
      const database = new MuxusDatabase(':memory:');
      try {
        if (withSequence) {
          const folder = database.upsertFolderSettings('Core', {});
          database.setFolderLoginSequence(folder.id, {
            steps: [
              { id: '1', kind: 'wait', pattern: '>', timeoutSeconds: 5 },
              { id: '2', kind: 'secret', secretId: 'enable-secret', enter: true },
            ],
          });
          database.updateOpenSshMetadata('router', { group: 'Core' });
        }
        const signals: AbortSignal[] = [];
        const vault = {
          secrets: () => [],
          externalSecret: (id: string) => ({ name: id, provider: 'fakevault', providerLabel: 'FakeVault', location: id }),
          secretValue: vi.fn((_id: string, _master: unknown, options: { signal: AbortSignal }) => {
            signals.push(options.signal);
            return Promise.resolve('value');
          }),
        };
        const { socket, stream, frames } = sshSession(database, {
          vault,
          // A hop password a key made unnecessary: read, never taken.
          connectShell: (shell, io) => {
            io.earlySecrets!.start(['hop-secret']);
            return Promise.resolve(shell);
          },
        });
        await vi.waitFor(() => expect(frames().some((frame) => frame.op === 'ready')).toBe(true));
        expect(signals.length).toBeGreaterThan(0);
        if (withSequence) {
          expect(signals.every((signal) => signal.aborted)).toBe(false);
          stream.emit('data', Buffer.from('router>'));
          await vi.waitFor(() =>
            expect(frames().filter((frame) => frame.op === 'login-sequence').at(-1)).toMatchObject({ state: 'done' }),
          );
        }
        await vi.waitFor(() => expect(signals.every((signal) => signal.aborted)).toBe(true));
        socket.close(1000, TERMINAL_SESSION_CLOSE_REASON);
      } finally {
        database.close();
      }
    }
  });

  it('runs nothing for an alias without a sequence', async () => {
    const database = new MuxusDatabase(':memory:');
    try {
      const { socket, stream, frames } = sshSession(database);
      await vi.waitFor(() => expect(frames().some((frame) => frame.op === 'ready')).toBe(true));
      stream.emit('data', Buffer.from('router>'));
      await new Promise((resolve) => setImmediate(resolve));
      expect(frames().some((frame) => frame.op === 'login-sequence')).toBe(false);
      expect(stream.write).not.toHaveBeenCalled();
      socket.close(1000, TERMINAL_SESSION_CLOSE_REASON);
    } finally {
      database.close();
    }
  });
});
