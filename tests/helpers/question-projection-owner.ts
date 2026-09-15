import type { PoolClient } from "pg";
import { loadAdmittedManagementQuestion } from "../../artifacts/server/src/question-projection-read.js";
import { ResponseAllocationManager } from "../../artifacts/server/src/response-allocation.js";

// Direct repository fixtures model producer/terminal/collector settlement here.
// This wrapper is not actual SDK/native-delivery or resource-audit evidence.
export async function readQuestionWithTestOwner(client: PoolClient, questionId: string) {
  const manager = new ResponseAllocationManager();
  const owner = manager.openRequest(new AbortController().signal);
  try {
    return await owner.produce(() => loadAdmittedManagementQuestion(client, questionId, "tool"));
  } finally {
    owner.nativeTerminal();
    owner.collectorSettled();
  }
}
