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

import { Template, Match } from '../../../../assertions';
import * as kms from '../../../../aws-kms';
import { App, Stack } from '../../../../core';
import { PolicyEngine } from '../../../lib';

describe('PolicyEngine', () => {
  let app: App;
  let stack: Stack;

  beforeEach(() => {
    app = new App();
    stack = new Stack(app, 'TestStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
  });

  test('creates policy engine with required properties', () => {
    new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::BedrockAgentCore::PolicyEngine', {
      Name: 'my-engine',
    });
  });

  test('creates policy engine with description', () => {
    new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
      description: 'Authorization engine for my agents',
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::BedrockAgentCore::PolicyEngine', {
      Name: 'my-engine',
      Description: 'Authorization engine for my agents',
    });
  });

  test('creates policy engine with KMS key', () => {
    const key = new kms.Key(stack, 'MyKey');

    new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
      kmsKey: key,
    });

    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::BedrockAgentCore::PolicyEngine', {
      Name: 'my-engine',
      EncryptionKeyArn: Match.anyValue(),
    });
  });

  test('exposes attributes', () => {
    const engine = new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
    });

    expect(engine.policyEngineName).toBe('my-engine');
    expect(engine.policyEngineId).toBeDefined();
    expect(engine.policyEngineArn).toBeDefined();
    expect(stack.resolve(engine.policyEngineArn)).toBeDefined();
  });

  test('auto-generates name when not provided', () => {
    const engine = new PolicyEngine(stack, 'TestEngine');

    expect(engine.policyEngineName).toBeDefined();
    expect(engine.policyEngineName.length).toBeGreaterThan(0);
  });

  test('fails for empty name', () => {
    expect(() => new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: '',
    })).toThrow(/Policy engine name/);
  });

  test('fails for name with invalid characters', () => {
    expect(() => new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my engine!',
    })).toThrow(/Policy engine name must contain only alphanumeric/);
  });

  test('fails for description exceeding 200 characters', () => {
    expect(() => new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
      description: 'x'.repeat(201),
    })).toThrow(/200 characters/);
  });

  test('import from attributes', () => {
    const imported = PolicyEngine.fromPolicyEngineAttributes(stack, 'Imported', {
      policyEngineArn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/my-engine',
      policyEngineId: 'engine-123',
      policyEngineName: 'my-engine',
    });

    expect(imported.policyEngineArn).toBe('arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/my-engine');
    expect(imported.policyEngineId).toBe('engine-123');
    expect(imported.policyEngineName).toBe('my-engine');
  });

  test('does not create encryption key permissions when no KMS key', () => {
    new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
    });

    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::KMS::Key', 0);
  });

  test('creates encryption key grant when KMS key is provided', () => {
    const key = new kms.Key(stack, 'MyKey');

    new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
      kmsKey: key,
    });

    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::KMS::Key', 1);
  });
});
