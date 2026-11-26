import { inspect } from "node:util";

const REDACTED = "[redacted]";

/**
 * A secret string (password, client secret, ...). The value is only available through
 * reveal(); JSON.stringify, String(), template literals, and util.inspect (console.error)
 * all print "[redacted]", so a secret cannot end up in a log line or response by accident.
 */
export class Secret {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  [inspect.custom](): string {
    return `Secret(${REDACTED})`;
  }
}
