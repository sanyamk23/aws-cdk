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
import { CfnPolicyEngine } from '../../../aws-bedrockagentcore';
import type { IPolicyEngineRef, PolicyEngineReference } from '../../../aws-bedrockagentcore';
import * as kms from '../../../aws-kms';
import { Resource, Token, Names, Lazy } from '../../../core';
import type { IResource, ResourceProps } from '../../../core';
import { addConstructMetadata } from '../../../core/lib/metadata-resource';
import { propertyInjectable } from '../../../core/lib/prop-injectable';
import { ValidationError } from '../../../core/lib/errors';
import { lit } from '../../../core/lib/helpers-internal';
import { validateStringFieldLength } from '../common/validation-helpers';

/**
 * Maximum length for a policy engine name
 * @internal
 */
const POLICY_ENGINE_NAME_MAX_LENGTH = 48;

/**
 * Minimum length for a policy engine name
 * @internal
 */
const POLICY_ENGINE_NAME_MIN_LENGTH = 1;

/**
 * Maximum length for a description
 * @internal
 */
const POLICY_ENGINE_DESCRIPTION_MAX_LENGTH = 200;

/**
 * Interface for PolicyEngine resources.
 */
export interface IPolicyEngine extends IResource, IPolicyEngineRef {
  /**
   * The ARN of the policy engine.
   * @attribute
   */
  readonly policyEngineArn: string;

  /**
   * The unique identifier of the policy engine.
   * @attribute
   */
  readonly policyEngineId: string;

  /**
   * The name of the policy engine.
   */
  readonly policyEngineName: string;

  /**
   * The KMS key used for encryption.
   */
  readonly kmsKey?: kms.IKey;

  /**
   * The status of the policy engine.
   * @attribute
   */
  readonly status?: string;

  /**
   * Timestamp when the policy engine was created.
   * @attribute
   */
  readonly createdAt?: string;

  /**
   * Timestamp when the policy engine was last updated.
   * @attribute
   */
  readonly updatedAt?: string;
}

/**
 * Attributes for importing an existing PolicyEngine.
 */
export interface PolicyEngineAttributes {
  /**
   * The ARN of the policy engine.
   */
  readonly policyEngineArn: string;

  /**
   * The unique identifier of the policy engine.
   */
  readonly policyEngineId: string;

  /**
   * The name of the policy engine.
   */
  readonly policyEngineName: string;
}

/**
 * Properties for defining a PolicyEngine.
 */
export interface PolicyEngineProps extends ResourceProps {
  /**
   * The customer-assigned immutable name for the policy engine.
   *
   * Must be unique within your account.
   * Valid characters are a-z, A-Z, 0-9, _ (underscore) and - (hyphen).
   * @default - A name is generated using `Names.uniqueResourceName`
   */
  readonly policyEngineName?: string;

  /**
   * A human-readable description of the policy engine's purpose and scope.
   * @default - No description
   */
  readonly description?: string;

  /**
   * The AWS KMS key used to encrypt data associated with the policy engine.
   * @default - No encryption
   */
  readonly kmsKey?: kms.IKey;
}

/**
 * An AWS Bedrock AgentCore PolicyEngine.
 *
 * A PolicyEngine manages Cedar authorization policies that control what
 * Bedrock agents can access. It acts as a container for policies and
 * evaluates authorization decisions against the associated policy set.
 *
 * @resource AWS::BedrockAgentCore::PolicyEngine
 * @see https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
 */
@propertyInjectable
export class PolicyEngine extends Resource implements IPolicyEngine {
  /** Uniquely identifies this class. */
  public static readonly PROPERTY_INJECTION_ID: string = 'aws-cdk-lib.aws-bedrockagentcore.PolicyEngine';

  /**
   * Import an existing PolicyEngine using its attributes.
   *
   * @param scope The construct scope
   * @param id The construct id
   * @param attrs The attributes of the existing PolicyEngine
   * @returns An IPolicyEngine instance representing the imported engine
   */
  public static fromPolicyEngineAttributes(
    scope: Construct,
    id: string,
    attrs: PolicyEngineAttributes,
  ): IPolicyEngine {
    class ImportedPolicyEngine extends Resource implements IPolicyEngine {
      public readonly policyEngineArn = attrs.policyEngineArn;
      public readonly policyEngineId = attrs.policyEngineId;
      public readonly policyEngineName = attrs.policyEngineName;
      public readonly kmsKey = undefined;
      public readonly status = undefined;
      public readonly createdAt = undefined;
      public readonly updatedAt = undefined;

      public get policyEngineRef(): PolicyEngineReference {
        return {
          policyEngineArn: this.policyEngineArn,
        };
      }

      constructor(s: Construct, i: string) {
        super(s, i);
      }
    }
    return new ImportedPolicyEngine(scope, id);
  }

  /**
   * The ARN of the policy engine.
   * @attribute
   */
  public readonly policyEngineArn: string;

  /**
   * The unique identifier of the policy engine.
   * @attribute
   */
  public readonly policyEngineId: string;

  /**
   * The name of the policy engine.
   */
  public readonly policyEngineName: string;

  /**
   * The KMS key used for encryption.
   */
  public readonly kmsKey?: kms.IKey;

  /**
   * The status of the policy engine.
   * @attribute
   */
  public readonly status?: string;

  /**
   * Timestamp when the policy engine was created.
   * @attribute
   */
  public readonly createdAt?: string;

  /**
   * Timestamp when the policy engine was last updated.
   * @attribute
   */
  public readonly updatedAt?: string;

  /**
   * A reference to the PolicyEngine resource.
   */
  public get policyEngineRef(): PolicyEngineReference {
    return {
      policyEngineArn: this.policyEngineArn,
    };
  }

  constructor(scope: Construct, id: string, props: PolicyEngineProps = {}) {
    super(scope, id, {
      physicalName: props.policyEngineName ??
        Lazy.string({ produce: () => Names.uniqueResourceName(this, { maxLength: POLICY_ENGINE_NAME_MAX_LENGTH }) }),
    });

    addConstructMetadata(this, props);

    this.policyEngineName = this.physicalName;
    this.validatePolicyEngineName(this.policyEngineName);

    this.kmsKey = props.kmsKey;

    if (props.description) {
      this.validateDescription(props.description);
    }

    const _resource = new CfnPolicyEngine(this, 'Resource', {
      name: this.policyEngineName,
      description: props.description,
      encryptionKeyArn: this.kmsKey?.keyArn,
    });

    this.policyEngineId = _resource.attrPolicyEngineId;
    this.policyEngineArn = _resource.attrPolicyEngineArn;
    this.status = _resource.attrStatus;
    this.createdAt = _resource.attrCreatedAt;
    this.updatedAt = _resource.attrUpdatedAt;
  }

  /**
   * Validates the policy engine name format.
   * @internal
   */
  private validatePolicyEngineName(name: string): void {
    if (Token.isUnresolved(name)) {
      return;
    }

    const lengthErrors = validateStringFieldLength({
      value: name,
      minLength: POLICY_ENGINE_NAME_MIN_LENGTH,
      maxLength: POLICY_ENGINE_NAME_MAX_LENGTH,
      fieldName: 'Policy engine name',
    });

    if (lengthErrors.length > 0) {
      throw new ValidationError(lit`PolicyEngineNameLengthInvalid`, lengthErrors.join('\n'), this);
    }

    const patternErrors: string[] = [];
    if (!/^([0-9a-zA-Z][-]?){1,48}$/.test(name)) {
      patternErrors.push('Policy engine name must contain only alphanumeric characters and hyphens, with hyphens only between characters');
    }

    if (patternErrors.length > 0) {
      throw new ValidationError(lit`PolicyEngineNamePatternInvalid`, patternErrors.join('\n'), this);
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
      maxLength: POLICY_ENGINE_DESCRIPTION_MAX_LENGTH,
      fieldName: 'Description',
    });

    if (errors.length > 0) {
      throw new ValidationError(lit`PolicyEngineDescriptionInvalid`, errors.join('\n'), this);
    }
  }
}
