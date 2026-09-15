import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse
} from "@simplewebauthn/server";

import {
  type CompleteWebAuthnAuthenticationInput,
  type CompleteWebAuthnRegistrationInput,
  type WebAuthnAttemptLimiter,
  type WebAuthnChallengeRecord,
  type WebAuthnCredentialRecord,
  type WebAuthnCrypto,
  type WebAuthnStore
} from "../../artifacts/server/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

export const allowAllWebAuthnAttempts: WebAuthnAttemptLimiter = {
  async consume() {
    return { allowed: true, retryAfterSeconds: 0 };
  }
};

export const ORIGIN = "https://boardagent.test";
export const RP_ID = "boardagent.test";
export const ORGANIZATION_ID = testId(60_001);
export const MEMBER_ID = testId(60_002);
export const SESSION_ID = testId(60_003);
export const REGISTRATION_CHALLENGE = Buffer.alloc(32, 0x52).toString("base64url");
export const AUTHENTICATION_CHALLENGE = Buffer.alloc(32, 0xa5).toString("base64url");
export const RAW_CREDENTIAL_ID = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
export const CREDENTIAL_ID = Buffer.from(RAW_CREDENTIAL_ID).toString("base64url");

export const registrationResponse: RegistrationResponseJSON = {
  id: CREDENTIAL_ID,
  rawId: CREDENTIAL_ID,
  type: "public-key",
  clientExtensionResults: {},
  authenticatorAttachment: "platform",
  response: {
    clientDataJSON: "registration-client-data",
    attestationObject: "registration-attestation",
    transports: ["internal"]
  }
};

export const authenticationResponse: AuthenticationResponseJSON = {
  id: CREDENTIAL_ID,
  rawId: CREDENTIAL_ID,
  type: "public-key",
  clientExtensionResults: {},
  authenticatorAttachment: "platform",
  response: {
    clientDataJSON: "authentication-client-data",
    authenticatorData: "authentication-data",
    signature: "authentication-signature"
  }
};

export class MemoryWebAuthnStore implements WebAuthnStore {
  public readonly challenges = new Map<string, WebAuthnChallengeRecord>();
  public readonly credentials = new Map<string, WebAuthnCredentialRecord>();

  public constructor(private readonly now: () => Date) {}

  public async saveChallenge(challenge: WebAuthnChallengeRecord): Promise<void> {
    if (
      [...this.challenges.values()].some(
        (stored) => stored.challengeSha256 === challenge.challengeSha256
      )
    ) {
      throw new Error("duplicate challenge");
    }
    this.challenges.set(challenge.id, { ...challenge });
  }

  public async findChallengeBySha256(
    organizationId: string,
    challengeSha256: string
  ): Promise<WebAuthnChallengeRecord | null> {
    const found = [...this.challenges.values()].find(
      (challenge) =>
        challenge.organizationId === organizationId && challenge.challengeSha256 === challengeSha256
    );
    return found ? { ...found } : null;
  }

  public async listActiveCredentials(
    organizationId: string,
    memberId: string
  ): Promise<readonly WebAuthnCredentialRecord[]> {
    return [...this.credentials.values()]
      .filter(
        (credential) =>
          credential.organizationId === organizationId &&
          credential.memberId === memberId &&
          credential.state === "active"
      )
      .map((credential) => cloneCredential(credential));
  }

  public async findActiveCredentialByRawId(
    organizationId: string,
    credentialId: Uint8Array
  ): Promise<WebAuthnCredentialRecord | null> {
    const encoded = Buffer.from(credentialId).toString("base64url");
    const found = [...this.credentials.values()].find(
      (credential) =>
        credential.organizationId === organizationId &&
        credential.state === "active" &&
        Buffer.from(credential.credentialId).toString("base64url") === encoded
    );
    return found ? cloneCredential(found) : null;
  }

  public async completeRegistration(input: CompleteWebAuthnRegistrationInput): Promise<boolean> {
    const challenge = this.challenges.get(input.challengeId);
    if (
      !challenge ||
      challenge.organizationId !== input.organizationId ||
      challenge.challengeSha256 !== input.expectedChallengeSha256 ||
      challenge.consumedAt !== null ||
      challenge.expiresAt.getTime() <= this.now().getTime() ||
      [...this.credentials.values()].some(
        (credential) =>
          Buffer.from(credential.credentialId).toString("base64url") ===
          Buffer.from(input.credential.credentialId).toString("base64url")
      )
    ) {
      return false;
    }
    this.challenges.set(challenge.id, { ...challenge, consumedAt: this.now() });
    this.credentials.set(input.credential.id, cloneCredential(input.credential));
    return true;
  }

  public async completeAuthentication(
    input: CompleteWebAuthnAuthenticationInput
  ): Promise<boolean> {
    const challenge = this.challenges.get(input.challengeId);
    const credential = this.credentials.get(input.credentialId);
    if (
      !challenge ||
      !credential ||
      challenge.organizationId !== input.organizationId ||
      credential.organizationId !== input.organizationId ||
      challenge.challengeSha256 !== input.expectedChallengeSha256 ||
      challenge.consumedAt !== null ||
      challenge.expiresAt.getTime() <= this.now().getTime() ||
      credential.state !== "active" ||
      credential.counter !== input.expectedCounter ||
      credential.backupEligible !== input.expectedBackupEligible ||
      ((credential.counter > 0 || input.newCounter > 0) &&
        input.newCounter <= credential.counter) ||
      (!credential.backupEligible && input.newBackupState)
    ) {
      return false;
    }
    this.challenges.set(challenge.id, { ...challenge, consumedAt: this.now() });
    this.credentials.set(credential.id, {
      ...cloneCredential(credential),
      counter: input.newCounter,
      backupState: input.newBackupState
    });
    return true;
  }
}

function cloneCredential(credential: WebAuthnCredentialRecord): WebAuthnCredentialRecord {
  return {
    ...credential,
    credentialId: Uint8Array.from(credential.credentialId),
    publicKey: Uint8Array.from(credential.publicKey),
    transports: [...credential.transports]
  };
}

export interface FakeCryptoControls {
  registrationVerified: boolean;
  registrationUserVerified: boolean;
  registrationDeviceType: "singleDevice" | "multiDevice";
  registrationBackedUp: boolean;
  authenticationVerified: boolean;
  authenticationUserVerified: boolean;
  authenticationDeviceType: "singleDevice" | "multiDevice";
  authenticationBackedUp: boolean;
  authenticationCounter: number;
  crossOrigin: boolean;
  throwRegistration: boolean;
  throwAuthentication: boolean;
}

export function fakeWebAuthnCrypto(controls: Partial<FakeCryptoControls> = {}): {
  readonly crypto: WebAuthnCrypto;
  readonly registrationCalls: Array<Parameters<WebAuthnCrypto["verifyRegistrationResponse"]>[0]>;
  readonly authenticationCalls: Array<
    Parameters<WebAuthnCrypto["verifyAuthenticationResponse"]>[0]
  >;
  readonly registrationOptionCalls: Array<
    Parameters<WebAuthnCrypto["generateRegistrationOptions"]>[0]
  >;
  readonly authenticationOptionCalls: Array<
    Parameters<WebAuthnCrypto["generateAuthenticationOptions"]>[0]
  >;
} {
  const state: FakeCryptoControls = {
    registrationVerified: true,
    registrationUserVerified: true,
    registrationDeviceType: "singleDevice",
    registrationBackedUp: false,
    authenticationVerified: true,
    authenticationUserVerified: true,
    authenticationDeviceType: "singleDevice",
    authenticationBackedUp: false,
    authenticationCounter: 1,
    crossOrigin: false,
    throwRegistration: false,
    throwAuthentication: false,
    ...controls
  };
  const registrationCalls: Array<Parameters<WebAuthnCrypto["verifyRegistrationResponse"]>[0]> = [];
  const authenticationCalls: Array<Parameters<WebAuthnCrypto["verifyAuthenticationResponse"]>[0]> =
    [];
  const registrationOptionCalls: Array<
    Parameters<WebAuthnCrypto["generateRegistrationOptions"]>[0]
  > = [];
  const authenticationOptionCalls: Array<
    Parameters<WebAuthnCrypto["generateAuthenticationOptions"]>[0]
  > = [];

  const registrationInfo: VerifiedRegistrationResponse = state.registrationVerified
    ? {
        verified: true,
        registrationInfo: {
          fmt: "none",
          aaguid: "00000000-0000-0000-0000-000000000000",
          credential: {
            id: CREDENTIAL_ID,
            publicKey: Uint8Array.from({ length: 64 }, () => 7),
            counter: 0,
            transports: ["internal"]
          },
          credentialType: "public-key",
          attestationObject: Uint8Array.from([1]),
          userVerified: state.registrationUserVerified,
          credentialDeviceType: state.registrationDeviceType,
          credentialBackedUp: state.registrationBackedUp,
          origin: ORIGIN,
          rpID: RP_ID
        }
      }
    : { verified: false };
  const authenticationInfo: VerifiedAuthenticationResponse = {
    verified: state.authenticationVerified,
    authenticationInfo: {
      credentialID: CREDENTIAL_ID,
      newCounter: state.authenticationCounter,
      userVerified: state.authenticationUserVerified,
      credentialDeviceType: state.authenticationDeviceType,
      credentialBackedUp: state.authenticationBackedUp,
      origin: ORIGIN,
      rpID: RP_ID
    }
  };

  return {
    registrationCalls,
    authenticationCalls,
    registrationOptionCalls,
    authenticationOptionCalls,
    crypto: {
      generateRegistrationOptions: async (options) => {
        registrationOptionCalls.push(options);
        return generateRegistrationOptions({
          ...options,
          challenge: Uint8Array.from(Buffer.from(REGISTRATION_CHALLENGE, "base64url"))
        });
      },
      verifyRegistrationResponse: async (options) => {
        registrationCalls.push(options);
        if (state.throwRegistration) throw new Error("registration rejected");
        return registrationInfo;
      },
      generateAuthenticationOptions: async (options) => {
        authenticationOptionCalls.push(options);
        return generateAuthenticationOptions({
          ...options,
          challenge: Uint8Array.from(Buffer.from(AUTHENTICATION_CHALLENGE, "base64url"))
        });
      },
      verifyAuthenticationResponse: async (options) => {
        authenticationCalls.push(options);
        if (state.throwAuthentication) throw new Error("authentication rejected");
        return authenticationInfo;
      },
      decodeClientDataJSON: (encoded) => ({
        type:
          encoded === registrationResponse.response.clientDataJSON
            ? "webauthn.create"
            : "webauthn.get",
        challenge:
          encoded === registrationResponse.response.clientDataJSON
            ? REGISTRATION_CHALLENGE
            : AUTHENTICATION_CHALLENGE,
        origin: ORIGIN,
        crossOrigin: state.crossOrigin
      })
    }
  };
}

export function idSequence(start = 60_100): () => string {
  let current = start;
  return () => {
    current += 1;
    return testId(current);
  };
}
