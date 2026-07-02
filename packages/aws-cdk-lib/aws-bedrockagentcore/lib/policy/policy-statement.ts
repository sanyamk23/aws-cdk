/**
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 *  with the License. A copy of the License is located at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
 *  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

import { Token } from '../../../core';
import { UnscopedValidationError } from '../../../core/lib/errors';
import { lit } from '../../../core/lib/helpers-internal';

/**
 * The effect of a Cedar policy statement.
 */
export enum PolicyEffect {
  /**
   * The statement permits the specified action.
   */
  PERMIT = 'permit',

  /**
   * The statement forbids the specified action.
   */
  FORBID = 'forbid',
}

/**
 * Properties for defining a PolicyStatement.
 */
export interface PolicyStatementProps {
  /**
   * The principal(s) this statement applies to.
   *
   * Can be a single principal string (e.g. `'AgentCore::OAuthUser::"user123"'`)
   * or an array of principals.
   *
   * @default - Applies to all principals (uses Cedar `principal` placeholder)
   */
  readonly principal?: string | string[];

  /**
   * The action(s) this statement applies to.
   *
   * Can be a single action string (e.g. `'AgentCore::Action::"GetData"'`)
   * or an array of actions.
   *
   * @default - Applies to all actions (uses Cedar `action` placeholder)
   */
  readonly action?: string | string[];

  /**
   * The resource(s) this statement applies to.
   *
   * Can be a single resource string (e.g. `'AgentCore::Gateway::"my-gateway"'`)
   * or an array of resources.
   *
   * @default - Applies to all resources (uses Cedar `resource` placeholder)
   */
  readonly resource?: string | string[];

  /**
   * Optional conditions for the policy statement.
   *
   * Conditions are key-value pairs that are evaluated at authorization time.
   * The keys are Cedar context attribute names and the values are the expected values.
   *
   * @default - No conditions
   */
  readonly conditions?: { [key: string]: string };
}

/**
 * A type-safe builder for Cedar policy statements.
 *
 * PolicyStatement provides a programmatic way to construct Cedar authorization
 * policies without writing raw Cedar syntax. Each statement defines an effect
 * (permit or forbid), optional principal and resource constraints, optional
 * action constraints, and optional conditions.
 *
 * Use the static factory methods `PolicyStatement.permit()` or
 * `PolicyStatement.forbid()` to create instances.
 *
 * @example
 * // Permit a specific agent to read data
 * const statement = PolicyStatement.permit({
 *   principal: 'AgentCore::OAuthUser::"user123"',
 *   action: ['AgentCore::Action::"GetData"', 'AgentCore::Action::"ListData"'],
 *   resource: 'AgentCore::Gateway::"my-gateway"',
 * });
 *
 * @example
 * // Forbid all write operations
 * const statement = PolicyStatement.forbid({
 *   action: 'AgentCore::Action::"PutData"',
 * });
 *
 * @see https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
 */
export class PolicyStatement {
  /**
   * Creates a new permit policy statement.
   *
   * @param props - Properties defining the statement constraints
   * @returns A new PolicyStatement with PERMIT effect
   */
  public static permit(props: PolicyStatementProps = {}): PolicyStatement {
    return new PolicyStatement(PolicyEffect.PERMIT, props);
  }

  /**
   * Creates a new forbid policy statement.
   *
   * @param props - Properties defining the statement constraints
   * @returns A new PolicyStatement with FORBID effect
   */
  public static forbid(props: PolicyStatementProps = {}): PolicyStatement {
    return new PolicyStatement(PolicyEffect.FORBID, props);
  }

  /**
   * The effect of this statement.
   */
  public readonly effect: PolicyEffect;

  private readonly _principal?: string[];
  private readonly _action: string[];
  private readonly _resource?: string[];
  private readonly _conditions?: { [key: string]: string };

  private constructor(effect: PolicyEffect, props: PolicyStatementProps = {}) {
    this.effect = effect;

    if (props.principal !== undefined) {
      const principals = Array.isArray(props.principal) ? props.principal : [props.principal];
      for (const p of principals) {
        if (!Token.isUnresolved(p) && p.trim().length === 0) {
          throw new UnscopedValidationError(lit`EmptyPrincipal`, 'Principal must not be an empty string');
        }
      }
      this._principal = principals;
    }

    const actions = props.action !== undefined ? (Array.isArray(props.action) ? props.action : [props.action]) : [];
    for (const a of actions) {
      if (!Token.isUnresolved(a) && a.trim().length === 0) {
        throw new UnscopedValidationError(lit`EmptyAction`, 'Action must not be an empty string');
      }
    }
    this._action = actions;

    if (props.resource !== undefined) {
      const resources = Array.isArray(props.resource) ? props.resource : [props.resource];
      for (const r of resources) {
        if (!Token.isUnresolved(r) && r.trim().length === 0) {
          throw new UnscopedValidationError(lit`EmptyResource`, 'Resource must not be an empty string');
        }
      }
      this._resource = resources;
    }

    this._conditions = props.conditions;
  }

  /**
   * Renders this statement as a Cedar policy string.
   *
   * @returns The Cedar policy statement string
   */
  public toCedar(): string {
    const parts: string[] = [];

    // Effect
    parts.push(this.effect);

    // Principal
    if (this._principal && this._principal.length > 0) {
      parts.push(`principal == ${this._principal.length === 1 ? this._principal[0] : `[${this._principal.join(', ')}]`}`);
    } else {
      parts.push('principal');
    }

    // Action
    if (this._action.length > 0) {
      parts.push(`action in [${this._action.join(', ')}]`);
    } else {
      parts.push('action');
    }

    // Resource
    if (this._resource && this._resource.length > 0) {
      parts.push(`resource == ${this._resource.length === 1 ? this._resource[0] : `[${this._resource.join(', ')}]`}`);
    } else {
      parts.push('resource');
    }

    // Conditions
    if (this._conditions && Object.keys(this._conditions).length > 0) {
      const conditionParts = Object.entries(this._conditions).map(([key, value]) => `${key} == "${value}"`);
      parts.push(`when { ${conditionParts.join(' && ')} }`);
    }

    return `${parts.join(' ')};`;
  }

  /**
   * Returns the principal constraint of this statement, if any.
   */
  public get principals(): string[] | undefined {
    return this._principal ? [...this._principal] : undefined;
  }

  /**
   * Returns the action constraint of this statement.
   */
  public get actions(): string[] {
    return [...this._action];
  }

  /**
   * Returns the resource constraint of this statement, if any.
   */
  public get resources(): string[] | undefined {
    return this._resource ? [...this._resource] : undefined;
  }

  /**
   * Returns the conditions of this statement, if any.
   */
  public get conditions(): { [key: string]: string } | undefined {
    return this._conditions ? { ...this._conditions } : undefined;
  }
}
