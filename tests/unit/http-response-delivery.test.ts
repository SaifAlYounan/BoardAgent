import { EventEmitter } from "node:events";

import { describe, expect, it } from "vitest";

import { writeWebResponse } from "../../artifacts/server/src/http-runtime.js";

class ResponseSink extends EventEmitter {
  public destroyed = false;
  public writableFinished = false;
  public ended = false;
  public readonly chunks: Uint8Array[] = [];
  public canContinue = true;
  public writeFailure: Error | undefined;

  public writeHead() {
    return this;
  }
  public write(chunk: Uint8Array) {
    if (this.writeFailure) throw this.writeFailure;
    this.chunks.push(chunk);
    return this.canContinue;
  }
  public end() {
    this.ended = true;
    return this;
  }
  public finish() {
    this.writableFinished = true;
    this.emit("finish");
  }
  public close() {
    this.destroyed = true;
    this.emit("close");
  }
  public response() {
    return this as unknown as Parameters<typeof writeWebResponse>[0];
  }
}

describe("resource response server handoff", () => {
  it("rejects finish while the source is still pending instead of claiming completion", async () => {
    const sink = new ResponseSink();
    const observations: unknown[] = [];
    let source: ReadableStreamDefaultController<Uint8Array> | undefined;
    const writing = writeWebResponse(
      sink.response(),
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            source = controller;
          }
        })
      ),
      false,
      (...observation) => observations.push(observation)
    );
    const result = writing.catch((error: unknown) => error);
    await new Promise<void>((resolve) => setImmediate(resolve));
    sink.finish();
    source!.error(new Error("source failed after premature finish"));
    expect(await result).toBeInstanceOf(Error);
    expect(observations).toEqual([["interrupted", 0, false]]);
    expect(sink.ended).toBe(false);
  });

  it("does not resolve completion merely because end was called", async () => {
    const sink = new ResponseSink();
    let settled = false;
    const writing = writeWebResponse(sink.response(), new Response("exact source"), false).then(
      () => {
        settled = true;
      }
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(sink.ended).toBe(true);
    expect(settled).toBe(false);
    sink.finish();
    await writing;
    expect(settled).toBe(true);
  });

  it("treats close during a pending source read as interruption", async () => {
    const sink = new ResponseSink();
    const writing = writeWebResponse(
      sink.response(),
      new Response(new ReadableStream<Uint8Array>()),
      false
    );
    const outcome = writing.then(
      () => "completed",
      () => "interrupted"
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    sink.close();
    expect(await outcome).toBe("interrupted");
    expect(sink.ended).toBe(false);
  });

  it("waits for drain and then actual finish", async () => {
    const sink = new ResponseSink();
    sink.canContinue = false;
    const observations: unknown[] = [];
    const writing = writeWebResponse(
      sink.response(),
      new Response("source"),
      false,
      (...observation) => observations.push(observation)
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(sink.chunks).toHaveLength(1);
    expect(sink.ended).toBe(false);
    expect(observations).toEqual([]);
    sink.emit("drain");
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(sink.ended).toBe(true);
    expect(observations).toEqual([]);
    sink.finish();
    await writing;
    sink.close();
    expect(observations).toEqual([["completed", 6, true]]);
    expect(sink.listenerCount("drain")).toBe(0);
  });

  it.each(["close", "error"])("interrupts %s while awaiting drain", async (event) => {
    const sink = new ResponseSink();
    sink.canContinue = false;
    const observations: unknown[] = [];
    const writing = writeWebResponse(
      sink.response(),
      new Response("source"),
      false,
      (...observation) => observations.push(observation)
    );
    const outcome = writing.then(
      () => "completed",
      () => "interrupted"
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (event === "close") sink.close();
    else sink.emit("error", new Error("synthetic response failure"));
    expect(await outcome).toBe("interrupted");
    sink.finish();
    expect(observations).toEqual([["interrupted", 6, true]]);
    expect(sink.ended).toBe(false);
    expect(sink.listenerCount("drain")).toBe(0);
    expect(sink.listenerCount("close")).toBe(0);
  });

  it("observes a throwing write without inventing known zero transferred bytes", async () => {
    const sink = new ResponseSink();
    const failure = new Error("synthetic synchronous write failure");
    sink.writeFailure = failure;
    const observations: unknown[] = [];
    await expect(
      writeWebResponse(sink.response(), new Response("source"), false, (...observation) =>
        observations.push(observation)
      )
    ).rejects.toBe(failure);
    expect(observations).toEqual([["interrupted", 0, true]]);
  });

  it.each([false, true])("observes a source failure afterWrite=%s", async (afterWrite) => {
    const sink = new ResponseSink();
    const failure = new RangeError("synthetic source failure");
    const observations: unknown[] = [];
    let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
    const body = new ReadableStream<Uint8Array>({
      start(value) {
        controller = value;
      }
    });
    const writing = writeWebResponse(sink.response(), new Response(body), false, (...observation) =>
      observations.push(observation)
    );
    const observed = writing.catch((error: unknown) => error);
    if (afterWrite) {
      controller!.enqueue(new Uint8Array([1, 2, 3]));
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    controller!.error(failure);
    expect(await observed).toBe(failure);
    expect(observations).toEqual([["interrupted", afterWrite ? 3 : 0, afterWrite]]);
    expect(body.locked).toBe(false);
  });

  it("observes an already locked source as an interruption before writing", async () => {
    const sink = new ResponseSink();
    const response = new Response("source");
    const existingReader = response.body!.getReader();
    const observations: unknown[] = [];
    await expect(
      writeWebResponse(sink.response(), response, false, (...observation) =>
        observations.push(observation)
      )
    ).rejects.toBeInstanceOf(TypeError);
    expect(observations).toEqual([["interrupted", 0, false]]);
    existingReader.releaseLock();
  });

  it("waits for finish on a response without a body", async () => {
    const sink = new ResponseSink();
    const observations: unknown[] = [];
    const writing = writeWebResponse(sink.response(), new Response(null), false, (...observation) =>
      observations.push(observation)
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(observations).toEqual([]);
    sink.finish();
    await writing;
    expect(observations).toEqual([["completed", 0, false]]);
  });

  it("does not write to a response that was already destroyed", async () => {
    const sink = new ResponseSink();
    sink.destroyed = true;
    const observations: unknown[] = [];
    await expect(
      writeWebResponse(sink.response(), new Response("source"), false, (...observation) =>
        observations.push(observation)
      )
    ).rejects.toThrow("connection closed");
    expect(sink.chunks).toEqual([]);
    expect(sink.ended).toBe(false);
    expect(observations).toEqual([["interrupted", 0, false]]);
  });
});
