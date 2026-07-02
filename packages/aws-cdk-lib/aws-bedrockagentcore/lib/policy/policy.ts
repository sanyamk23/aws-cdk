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

import type { Construct } from 'constructs';
import { CfnPolicy } from '../../../aws-bedrockagentcore';
import type { IPolicyRef, PolicyReference } from '../../../aws-bedrockagentcore';
import { Resource, Token, Names, Lazy } from '../../../core';
import type { IResource, ResourceProps } from '../../../core';
import { addConstructMetadata } from '../../../core/lib/metadata-resource';
import { propertyInjectable } from '../../../core/lib/prop-injectable';
import { ValidationError } from '../../../core/lib/errors';
import { lit } from '../../../core/lib/helpers-internal';
import { validateStringFieldLength } from '../common/validation-helpers';
import type { IPolicyEngine } from './policy-engine';
import type { PolicyStatement } from './policy-statement';

/**
 * Maximum length for a policy name
 * @internal
 */
const POLICY_NAME_MAX_LENGTH = 48;

/**
 * Minimum length for a policy name
 * @internal
 */
const POLICY_NAME_MIN_LENGTH = 1;

/**
 * Maximum length for a description
 * @internal
 */
const POLICY_DESCRIPTION_MAX_LENGTH = 200;

/**
 * The validation mode for a policy.
 *
 * Determines how Cedar analyzer validation results are handled.
 */
export enum ValidationMode {
  /**
   * Strict validation mode — the policy is rejected if the Cedar analyzer
   * produces any validation errors.
   */
  STRICT = 'STRICT',
}

/**
 * Interface for Policy resources.
 */
export interface IPolicy extends IResource, IPolicyRef {
  /**
   * The ARN of the policy.
   * @attribute
   */
  readonly policyArn: string;

  /**
   * The unique identifier of the policy.
   * @attribute
   */
  readonly policyId: string;

  /**
   * The name of the policy.
   */
  readonly policyName: string;

  /**
   * The Cedar policy statement string.
   */
  readonly cedarPolicy: string;

  /**
   * The status of the policy.
   * @attribute
   */
  readonly status?: string;

  /**
   * Timestamp when the policy was created.
   * @attribute
   */
  readonly createdAt?: string;

  /**
   * Timestamp when the policy was last updated.
   * @attribute
   */
  readonly updatedAt?: string;
}

/**
 * Attributes for importing an existing Policy.
 */
export interface PolicyAttributes {
  /**
   * The ARN of the policy.
   */
  readonly policyArn: string;

  /**
   * The unique identifier of the policy.
   */
  readonly policyId: string;

  /**
   * The name of the policy.
   */
  readonly policyName: string;

  /**
   * The Cedar policy statement string.
   */
  readonly cedarPolicy: string;
}

/**
 * Properties for defining a Policy.
 */
export interface PolicyProps extends ResourceProps {
  /**
   * The policy engine to associate this policy with.
   */
  readonly policyEngine: IPolicyEngine;

  /**
   * The customer-assigned immutable name for the policy.
   *
   * Must be unique within the associated policy engine.
   * Valid characters are a-z, A-Z, 0-9, _ (underscore) and - (hyphen).
   * @default - A name is generated using `Names.uniqueResourceName`
   */
  readonly policyName?: string;

  /**
   * A human-readable description of the policy's purpose and functionality.
   * @default - No description
   */
  readonly description?: string;

  /**
   * A Cedar policy statement defining the authorization logic.
   *
   * Use `PolicyStatement.permit()` or `PolicyStatement.forbid()` to create
   * type-safe policy statements without writing raw Cedar syntax.
   *
   * Mutually exclusive with `definition`.
   *
   * @default - No statement (requires `definition`)
   */
  readonly statement?: PolicyStatement;

  /**
   * A raw Cedar policy definition string.
   *
   * Use this when you need full control over the Cedar syntax and the
   * type-safe builder does not cover your use case.
   *
   * Mutually exclusive with `statement`.
   *
   * @default - No raw definition (requires `statement`)
   */
  readonly definition?: string;

  /**
   * The validation mode for the policy.
   *
   * Determines how Cedar analyzer validation results are handled.
   * @default - No validation mode (service default)
   */
  readonly validationMode?: ValidationMode;
}

/**
 * An AWS Bedrock AgentCore Policy.
 *
 * A Policy defines Cedar authorization rules that control what Bedrock agents
 * can access. Policies are associated with a PolicyEngine and evaluated
 * against incoming authorization requests.
 *
 * Use `PolicyStatement.permit()` or `PolicyStatement.forbid()` to create
 * type-safe Cedar policies without writing raw Cedar syntax, or provide
 * a raw Cedar string via the `definition` prop.
 *
 * @resource AWS::BedrockAgentCore::Policy
 * @see https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
 */
@propertyInjectable
export class Policy extends Resource implements IPolicy {
  /** Uniquely identifies this class. */
  public static readonly PROPERTY_INJECTION_ID: string = 'aws-cdk-lib.aws-bedrockagentcore.Policy';

  /**
   * Import an existing Policy using its attributes.
   *
   * @param scope The construct scope
   * @param id The construct id
   * @param attrs The attributes of the existing Policy
   * @returns An IPolicy instance representing the imported policy
   */
  public static fromPolicyAttributes(
    scope: Construct,
    id: string,
    attrs: PolicyAttributes,
  ): IPolicy {
    class ImportedPolicy extends Resource implements IPolicy {
      public readonly policyArn = attrs.policyArn;
      public readonly policyId = attrs.policyId;
      public readonly policyName = attrs.policyName;
      public readonly cedarPolicy = attrs.cedarPolicy;
      public readonly status = undefined;
      public readonly createdAt = undefined;
      public readonly updatedAt = undefined;

      public get policyRef(): PolicyReference {
        return {
          policyArn: this.policyArn,
        };
      }

      constructor(s: Construct, i: string) {
        super(s, i);
      }
    }
    return new ImportedPolicy(scope, id);
  }

  /**
   * The ARN of the policy.
   * @attribute
   */
  public readonly policyArn: string;

  /**
   * The unique identifier of the policy.
   * @attribute
   */
  public readonly policyId: string;

  /**
   * The name of the policy.
   */
  public readonly policyName: string;

  /**
   * The Cedar policy statement string.
   */
  public readonly cedarPolicy: string;

  /**
   * The status of the policy.
   * @attribute
   */
  public readonly status?: string;

  /**
   * Timestamp when the policy was created.
   * @attribute
   */
  public readonly createdAt?: string;

  /**
   * Timestamp when the policy was last updated.
   * @attribute
   */
  public readonly updatedAt?: string;

  /**
   * A reference to the Policy resource.
   */
  public get policyRef(): PolicyReference {
    return {
      policyArn: this.policyArn,
    };
  }

  constructor(scope: Construct, id: string, props: PolicyProps) {
    super(scope, id, {
      physicalName: props.policyName ??
        Lazy.string({ produce: () => Names.uniqueResourceName(this, { maxLength: POLICY_NAME_MAX_LENGTH }) }),
    });

    addConstructMetadata(this, props);

    this.policyName = this.physicalName;
    this.validatePolicyName(this.policyName);

    if (props.description) {
      this.validateDescription(props.description);
    }

    // Resolve Cedar policy from statement or raw definition
    const cedarPolicy = this.resolveCedarPolicy(props);

    const _resource = new CfnPolicy(this, 'Resource', {
      name: this.policyName,
      policyEngineId: props.policyEngine.policyEngineId,
      description: props.description,
      definition: {
        cedar: {
          statement: cedarPolicy,
        },
      },
      validationMode: props.validationMode,
    });

    this.policyId = _resource.attrPolicyId;
    this.policyArn = _resource.attrPolicyArn;
    this.cedarPolicy = cedarPolicy;
    this.status = _resource.attrStatus;
    this.createdAt = _resource.attrCreatedAt;
    this.updatedAt = _resource.attrUpdatedAt;
  }

  /**
   * Resolves the Cedar policy string from props.
   * @internal
   */
  private resolveCedarPolicy(props: PolicyProps): string {
    if (props.statement && props.definition) {
      throw new ValidationError(
        lit`ConflictingPolicyDefinition`,
        'Cannot specify both `statement` and `definition`. Use one or the other.',
        this,
      );
    }

    if (!props.statement && !props.definition) {
      throw new ValidationError(
        lit`MissingPolicyDefinition`,
        'Either `statement` or `definition` must be specified.',
        this,
      );
    }

    if (props.definition) {
      if (!Token.isUnresolved(props.definition) && props.definition.trim().length === 0) {
        throw new ValidationError(lit`EmptyPolicyDefinition`, 'Policy definition must not be an empty string', this);
      }
      return props.definition;
    }

    return props.statement!.toCedar();
  }

  /**
   * Validates the policy name format.
   * @internal
   */
  private validatePolicyName(name: string): void {
    if (Token.isUnresolved(name)) {
      return;
    }

    const lengthErrors = validateStringFieldLength({
      value: name,
      minLength: POLICY_NAME_MIN_LENGTH,
      maxLength: POLICY_NAME_MAX_LENGTH,
      fieldName: 'Policy name',
    });

    if (lengthErrors.length > 0) {
      throw new ValidationError(lit`PolicyNameLengthInvalid`, lengthErrors.join('\n'), this);
    }

    const patternErrors: string[] = [];
    if (!/^([0-9a-zA-Z][-]?){1,48}$/.test(name)) {
      patternErrors.push('Policy name must contain only alphanumeric characters and hyphens, with hyphens only between characters');
    }

    if (patternErrors.length > 0) {
      throw new ValidationError(lit`PolicyNamePatternInvalid`, patternErrors.join('\n'), this);
    }
  }

  /**
   * Validates the description format.
   * @internal
   */
  private validateDescription(description: string): void {
    if (Token.isUnresolved(description)) {
      return;
    }

    const errors = validateStringFieldLength({
      value: description,
      minLength: 1,
      maxLength: POLICY_DESCRIPTION_MAX_LENGTH,
      fieldName: 'Description',
    });

    if (errors.length > 0) {
      throw new ValidationError(lit`PolicyDescriptionInvalid`, errors.join('\n'), this);
    }
  }
}
