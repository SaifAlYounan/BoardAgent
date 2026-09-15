import type { Pool } from "pg";

/** pg removes a failed idle client itself. Observe the pool event without exposing
 * its Error/client objects, which may contain connection credentials. */
export function observeDatabasePoolErrors(pool: Pool, report?: () => void | Promise<void>) {
  const fallback = () => {
    process.stderr.write('{"event":"database_connection_lost","status":"error"}\n');
  };
  const onError = () => {
    if (!report) {
      fallback();
      return;
    }
    try {
      void Promise.resolve(report()).catch(fallback);
    } catch {
      fallback();
    }
  };
  pool.on("error", onError);
  return () => {
    pool.removeListener("error", onError);
  };
}
