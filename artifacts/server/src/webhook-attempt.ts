/** A transport may emit this only for a proven failure before TCP connection. */
export class WebhookPreconnectError extends Error {
  public constructor(
    public readonly address: string,
    options?: ErrorOptions
  ) {
    super("webhook connection failed before TCP connection", options);
    this.name = "WebhookPreconnectError";
  }
}

export class WebhookAttemptDeadlineError extends Error {
  public constructor() {
    super("webhook delivery attempt timed out");
    this.name = "WebhookAttemptDeadlineError";
  }
}

export class WebhookAttemptAbortedError extends Error {
  public constructor() {
    super("webhook delivery attempt aborted");
    this.name = "WebhookAttemptAbortedError";
  }
}

/** No I/O here: ports own validation/delivery; one budget includes both. */
export async function runWebhookAttempt<T>(input: {
  readonly signal: AbortSignal;
  readonly validate: () => Promise<readonly string[]>;
  readonly deliver: (address: string, signal: AbortSignal) => Promise<T>;
}): Promise<T> {
  if (input.signal.aborted) throw new WebhookAttemptAbortedError();
  const controller = new AbortController();
  const expiresAt = performance.now() + 10_000;
  const abort = (): void => controller.abort(new WebhookAttemptAbortedError());
  const deadline = setTimeout(() => controller.abort(new WebhookAttemptDeadlineError()), 10_000);
  input.signal.addEventListener("abort", abort, { once: true });
  if (input.signal.aborted) abort();
  const assertActive = (): void => {
    if (!controller.signal.aborted && performance.now() >= expiresAt) {
      controller.abort(new WebhookAttemptDeadlineError());
    }
    if (controller.signal.aborted) throw controller.signal.reason;
  };
  const step = <U>(run: () => Promise<U>): Promise<U> => {
    assertActive();
    return new Promise<U>((resolve, reject) => {
      let settled = false;
      const finish = (complete: () => void): void => {
        if (settled) return;
        settled = true;
        controller.signal.removeEventListener("abort", interrupted);
        complete();
      };
      const interrupted = (): void => finish(() => reject(controller.signal.reason));
      controller.signal.addEventListener("abort", interrupted, { once: true });
      try {
        assertActive();
        // Observe both late outcomes. A timed-out lookup may finish in the OS, but
        // its result can neither start delivery nor become an unhandled rejection.
        Promise.resolve(run()).then(
          (value) => {
            try {
              assertActive();
              finish(() => resolve(value));
            } catch (error) {
              finish(() => reject(error));
            }
          },
          (error: unknown) => {
            try {
              assertActive();
              finish(() => reject(error));
            } catch (interruption) {
              finish(() => reject(interruption));
            }
          }
        );
      } catch (error) {
        finish(() => reject(error));
      }
    });
  };
  try {
    const addresses = [...(await step(input.validate))];
    if (
      addresses.length < 1 ||
      addresses.length > 16 ||
      new Set(addresses).size !== addresses.length ||
      addresses.some((address) => typeof address !== "string" || address.length === 0)
    ) {
      throw new Error("webhook validated address set is invalid");
    }
    let lastFailure: WebhookPreconnectError | undefined;
    for (const address of addresses) {
      assertActive();
      try {
        return await step(() => input.deliver(address, controller.signal));
      } catch (error) {
        assertActive();
        if (!(error instanceof WebhookPreconnectError) || error.address !== address) throw error;
        lastFailure = error;
      }
    }
    throw lastFailure ?? new Error("webhook validated address set is unavailable");
  } finally {
    clearTimeout(deadline);
    input.signal.removeEventListener("abort", abort);
  }
}
