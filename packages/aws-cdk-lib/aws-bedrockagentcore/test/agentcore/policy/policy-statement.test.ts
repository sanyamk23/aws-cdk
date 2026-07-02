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

import { PolicyStatement, PolicyEffect } from '../../../lib';

describe('PolicyStatement', () => {
  describe('permit', () => {
    test('creates a permit statement with all constraints', () => {
      const statement = PolicyStatement.permit({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: ['AgentCore::Action::"GetData"', 'AgentCore::Action::"ListData"'],
        resource: 'AgentCore::Gateway::"my-gateway"',
      });

      expect(statement.effect).toBe(PolicyEffect.PERMIT);
      expect(statement.principals).toEqual(['AgentCore::OAuthUser::"user123"']);
      expect(statement.actions).toEqual(['AgentCore::Action::"GetData"', 'AgentCore::Action::"ListData"']);
      expect(statement.resources).toEqual(['AgentCore::Gateway::"my-gateway"']);
    });

    test('renders correct Cedar syntax with single principal and resource', () => {
      const statement = PolicyStatement.permit({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: 'AgentCore::Action::"GetData"',
        resource: 'AgentCore::Gateway::"my-gateway"',
      });

      expect(statement.toCedar()).toBe(
        'permit principal == AgentCore::OAuthUser::"user123" action in [AgentCore::Action::"GetData"] resource == AgentCore::Gateway::"my-gateway";',
      );
    });

    test('renders correct Cedar syntax with multiple actions', () => {
      const statement = PolicyStatement.permit({
        action: ['AgentCore::Action::"GetData"', 'AgentCore::Action::"ListData"'],
      });

      expect(statement.toCedar()).toBe(
        'permit principal action in [AgentCore::Action::"GetData", AgentCore::Action::"ListData"] resource;',
      );
    });

    test('renders correct Cedar syntax with conditions', () => {
      const statement = PolicyStatement.permit({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: 'AgentCore::Action::"GetData"',
        conditions: { 'aws:PrincipalTag/department': 'engineering' },
      });

      expect(statement.toCedar()).toBe(
        'permit principal == AgentCore::OAuthUser::"user123" action in [AgentCore::Action::"GetData"] resource when { aws:PrincipalTag/department == "engineering" };',
      );
    });

    test('renders correct Cedar syntax with multiple conditions', () => {
      const statement = PolicyStatement.permit({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: 'AgentCore::Action::"GetData"',
        conditions: {
          'aws:PrincipalTag/department': 'engineering',
          'aws:PrincipalTag/region': 'us-east-1',
        },
      });

      const cedar = statement.toCedar();
      expect(cedar).toContain('when {');
      expect(cedar).toContain('aws:PrincipalTag/department == "engineering"');
      expect(cedar).toContain('aws:PrincipalTag/region == "us-east-1"');
    });
  });

  describe('forbid', () => {
    test('creates a forbid statement', () => {
      const statement = PolicyStatement.forbid({
        action: 'AgentCore::Action::"PutData"',
      });

      expect(statement.effect).toBe(PolicyEffect.FORBID);
    });

    test('renders correct Cedar syntax', () => {
      const statement = PolicyStatement.forbid({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: 'AgentCore::Action::"PutData"',
        resource: 'AgentCore::Gateway::"my-gateway"',
      });

      expect(statement.toCedar()).toBe(
        'forbid principal == AgentCore::OAuthUser::"user123" action in [AgentCore::Action::"PutData"] resource == AgentCore::Gateway::"my-gateway";',
      );
    });
  });

  describe('defaults', () => {
    test('creates statement with no constraints', () => {
      const statement = PolicyStatement.permit();

      expect(statement.effect).toBe(PolicyEffect.PERMIT);
      expect(statement.principals).toBeUndefined();
      expect(statement.actions).toEqual([]);
      expect(statement.resources).toBeUndefined();
    });

    test('renders bare Cedar syntax with no constraints', () => {
      const statement = PolicyStatement.permit();
      expect(statement.toCedar()).toBe('permit principal action resource;');
    });
  });

  describe('multiple principals', () => {
    test('renders array syntax for multiple principals', () => {
      const statement = PolicyStatement.permit({
        principal: ['AgentCore::OAuthUser::"user1"', 'AgentCore::OAuthUser::"user2"'],
        action: 'AgentCore::Action::"GetData"',
      });

      expect(statement.toCedar()).toContain(
        'principal == [AgentCore::OAuthUser::"user1", AgentCore::OAuthUser::"user2"]',
      );
    });
  });

  describe('multiple resources', () => {
    test('renders array syntax for multiple resources', () => {
      const statement = PolicyStatement.permit({
        action: 'AgentCore::Action::"GetData"',
        resource: ['AgentCore::Gateway::"gw1"', 'AgentCore::Gateway::"gw2"'],
      });

      expect(statement.toCedar()).toContain(
        'resource == [AgentCore::Gateway::"gw1", AgentCore::Gateway::"gw2"]',
      );
    });
  });

  describe('validation', () => {
    test('fails for empty principal string', () => {
      expect(() => PolicyStatement.permit({
        principal: '',
        action: 'AgentCore::Action::"GetData"',
      })).toThrow(/Principal must not be an empty string/);
    });

    test('fails for empty action string', () => {
      expect(() => PolicyStatement.permit({
        action: '',
      })).toThrow(/Action must not be an empty string/);
    });

    test('fails for empty resource string', () => {
      expect(() => PolicyStatement.permit({
        action: 'AgentCore::Action::"GetData"',
        resource: '',
      })).toThrow(/Resource must not be an empty string/);
    });

    test('fails for whitespace-only principal', () => {
      expect(() => PolicyStatement.permit({
        principal: '   ',
        action: 'AgentCore::Action::"GetData"',
      })).toThrow(/Principal must not be an empty string/);
    });
  });

  describe('getters', () => {
    test('returns copies of internal arrays', () => {
      const statement = PolicyStatement.permit({
        principal: 'AgentCore::OAuthUser::"user123"',
        action: 'AgentCore::Action::"GetData"',
        resource: 'AgentCore::Gateway::"my-gateway"',
      });

      const principals1 = statement.principals;
      const principals2 = statement.principals;
      expect(principals1).not.toBe(principals2);
      expect(principals1).toEqual(principals2);

      const actions1 = statement.actions;
      const actions2 = statement.actions;
      expect(actions1).not.toBe(actions2);
      expect(actions1).toEqual(actions2);
    });

    test('returns copy of conditions', () => {
      const statement = PolicyStatement.permit({
        action: 'AgentCore::Action::"GetData"',
        conditions: { key: 'value' },
      });

      const conds1 = statement.conditions;
      const conds2 = statement.conditions;
      expect(conds1).not.toBe(conds2);
      expect(conds1).toEqual(conds2);
    });
  });
});
