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
import { App, Stack } from '../../../../core';
import {
  PolicyEngine,
  Policy,
  PolicyStatement,
  ValidationMode,
} from '../../../lib';

describe('Policy', () => {
  let app: App;
  let stack: Stack;
  let engine: PolicyEngine;

  beforeEach(() => {
    app = new App();
    stack = new Stack(app, 'TestStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
    engine = new PolicyEngine(stack, 'TestEngine', {
      policyEngineName: 'my-engine',
    });
  });

  describe('with statement', () => {
    test('creates policy from PolicyStatement', () => {
      new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          principal: 'AgentCore::OAuthUser::"user123"',
          action: 'AgentCore::Action::"GetData"',
          resource: 'AgentCore::Gateway::"my-gateway"',
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
        Name: 'my-policy',
        PolicyEngineId: Match.anyValue(),
        Definition: {
          Cedar: {
            Statement: 'permit principal == AgentCore::OAuthUser::"user123" action in [AgentCore::Action::"GetData"] resource == AgentCore::Gateway::"my-gateway";',
          },
        },
      });
    });

    test('creates policy with forbid statement', () => {
      new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'deny-policy',
        statement: PolicyStatement.forbid({
          principal: 'AgentCore::OAuthUser::"user123"',
          action: 'AgentCore::Action::"DeleteData"',
          resource: 'AgentCore::Gateway::"my-gateway"',
        }),
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
        Definition: {
          Cedar: {
            Statement: Match.stringLikeRegexp('^forbid .*'),
          },
        },
      });
    });

    test('creates policy with description', () => {
      new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
        description: 'Allows read access to all agents',
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
        Description: 'Allows read access to all agents',
      });
    });

    test('creates policy with validation mode', () => {
      new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
        validationMode: ValidationMode.STRICT,
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
        ValidationMode: 'STRICT',
      });
    });
  });

  describe('with raw definition', () => {
    test('creates policy from raw Cedar string', () => {
      new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'raw-policy',
        definition: 'permit(principal, action, resource);',
      });

      const template = Template.fromStack(stack);
      template.hasResourceProperties('AWS::BedrockAgentCore::Policy', {
        Name: 'raw-policy',
        Definition: {
          Cedar: {
            Statement: 'permit(principal, action, resource);',
          },
        },
      });
    });
  });

  describe('validation', () => {
    test('fails when both statement and definition are provided', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
        definition: 'permit(principal, action, resource);',
      })).toThrow(/Cannot specify both/);
    });

    test('fails when neither statement nor definition is provided', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
      })).toThrow(/Either `statement` or `definition` must be specified/);
    });

    test('fails for empty policy name', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: '',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
      })).toThrow(/Policy name/);
    });

    test('fails for name with invalid characters', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my policy!',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
      })).toThrow(/Policy name must contain only alphanumeric/);
    });

    test('fails for empty raw definition', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        definition: '   ',
      })).toThrow(/Policy definition must not be an empty string/);
    });

    test('fails for description exceeding 200 characters', () => {
      expect(() => new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
        description: 'x'.repeat(201),
      })).toThrow(/200 characters/);
    });
  });

  describe('exposed attributes', () => {
    test('exposes policy attributes', () => {
      const policy = new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        policyName: 'my-policy',
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
      });

      expect(policy.policyName).toBe('my-policy');
      expect(policy.policyId).toBeDefined();
      expect(policy.policyArn).toBeDefined();
      expect(policy.cedarPolicy).toBe(
        'permit principal action in [AgentCore::Action::"GetData"] resource;',
      );
    });
  });

  describe('import', () => {
    test('import from attributes', () => {
      const imported = Policy.fromPolicyAttributes(stack, 'Imported', {
        policyArn: 'arn:aws:bedrock-agentcore:us-east-1:123456789012:policy/my-policy',
        policyId: 'policy-123',
        policyName: 'my-policy',
        cedarPolicy: 'permit(principal, action, resource);',
      });

      expect(imported.policyArn).toBe('arn:aws:bedrock-agentcore:us-east-1:123456789012:policy/my-policy');
      expect(imported.policyId).toBe('policy-123');
      expect(imported.policyName).toBe('my-policy');
      expect(imported.cedarPolicy).toBe('permit(principal, action, resource);');
    });
  });

  describe('multiple policies on same engine', () => {
    test('creates multiple policies associated with the same engine', () => {
      new Policy(stack, 'Policy1', {
        policyEngine: engine,
        policyName: 'read-policy',
        statement: PolicyStatement.permit({
          principal: 'AgentCore::OAuthUser::"user123"',
          action: 'AgentCore::Action::"GetData"',
        }),
      });

      new Policy(stack, 'Policy2', {
        policyEngine: engine,
        policyName: 'write-policy',
        statement: PolicyStatement.forbid({
          principal: 'AgentCore::OAuthUser::"user123"',
          action: 'AgentCore::Action::"DeleteData"',
        }),
      });

      const template = Template.fromStack(stack);
      template.resourceCountIs('AWS::BedrockAgentCore::Policy', 2);
    });
  });

  describe('auto-generated name', () => {
    test('generates a name when not provided', () => {
      const policy = new Policy(stack, 'TestPolicy', {
        policyEngine: engine,
        statement: PolicyStatement.permit({
          action: 'AgentCore::Action::"GetData"',
        }),
      });

      expect(policy.policyName).toBeDefined();
      expect(policy.policyName.length).toBeGreaterThan(0);
    });
  });
});
