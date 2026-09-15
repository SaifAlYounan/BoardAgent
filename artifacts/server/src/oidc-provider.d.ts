declare module "oidc-provider" {
  import type { RequestListener } from "node:http";

  export interface ProviderConfiguration {
    readonly [key: string]: unknown;
  }

  export interface InteractionDetails {
    readonly uid: string;
    readonly prompt: {
      readonly name: string;
      readonly details?: Readonly<Record<string, unknown>>;
    };
    readonly params: Readonly<Record<string, unknown>>;
    readonly session?: { readonly accountId?: string };
    readonly grantId?: string;
  }

  export class Provider {
    public constructor(issuer: string, configuration: ProviderConfiguration);
    public readonly issuer: string;
    public proxy: boolean;
    public callback(): RequestListener;
    public interactionDetails(request: unknown, response: unknown): Promise<InteractionDetails>;
    public interactionResult(
      request: unknown,
      response: unknown,
      result: Readonly<Record<string, unknown>>,
      options?: { readonly mergeWithLastSubmission?: boolean }
    ): Promise<string>;
    public interactionFinished(
      request: unknown,
      response: unknown,
      result: Readonly<Record<string, unknown>>,
      options?: { readonly mergeWithLastSubmission?: boolean }
    ): Promise<void>;
    public urlFor(name: string): string;
  }

  const DefaultProvider: typeof Provider;
  export default DefaultProvider;

  export const errors: {
    readonly InvalidTarget: new (description?: string) => Error;
    readonly InvalidRequest: new (description?: string) => Error;
  };
}
