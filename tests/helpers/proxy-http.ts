import { request } from "node:http";

// Native HTTP preserves the canonical Host supplied by a TLS-offload proxy.
// Fetch may replace Host with the loopback transport address.
export async function proxyHttpRequest(
  url: URL | string,
  headers: Readonly<Record<string, string>>,
  options: { readonly method?: "GET" | "POST"; readonly body?: string } = {}
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const outbound = request(
      url,
      { headers, method: options.method ?? "GET", signal: AbortSignal.timeout(10_000) },
      (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
        incoming.once("error", reject);
        incoming.once("end", () => {
          const responseHeaders = new Headers();
          for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
            responseHeaders.append(incoming.rawHeaders[index]!, incoming.rawHeaders[index + 1]!);
          }
          resolve(
            new Response(Buffer.concat(chunks), {
              status: incoming.statusCode!,
              headers: responseHeaders
            })
          );
        });
      }
    );
    outbound.once("error", reject);
    outbound.end(options.body);
  });
}
