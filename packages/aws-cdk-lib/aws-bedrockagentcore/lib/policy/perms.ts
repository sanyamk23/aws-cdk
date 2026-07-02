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

/******************************************************************************
 * Control Plane Permissions
 *****************************************************************************/

/**
 * Get permissions for policy engine resources
 */
export const POLICY_ENGINE_GET_PERMS = ['bedrock-agentcore:GetPolicyEngine'];

/**
 * List permissions for policy engine resources
 */
export const POLICY_ENGINE_LIST_PERMS = ['bedrock-agentcore:ListPolicyEngines'];

/**
 * Create permissions for policy engine resources
 */
export const POLICY_ENGINE_CREATE_PERMS = ['bedrock-agentcore:CreatePolicyEngine'];

/**
 * Update permissions for policy engine resources
 */
export const POLICY_ENGINE_UPDATE_PERMS = ['bedrock-agentcore:UpdatePolicyEngine'];

/**
 * Delete permissions for policy engine resources
 */
export const POLICY_ENGINE_DELETE_PERMS = ['bedrock-agentcore:DeletePolicyEngine'];

/**
 * Combined manage permissions (create, update, delete)
 */
export const POLICY_ENGINE_MANAGE_PERMS = [...new Set([...POLICY_ENGINE_CREATE_PERMS, ...POLICY_ENGINE_UPDATE_PERMS, ...POLICY_ENGINE_DELETE_PERMS])];

/**
 * Get permissions for policy resources
 */
export const POLICY_GET_PERMS = ['bedrock-agentcore:GetPolicy'];

/**
 * List permissions for policy resources
 */
export const POLICY_LIST_PERMS = ['bedrock-agentcore:ListPolicies'];

/**
 * Create permissions for policy resources
 */
export const POLICY_CREATE_PERMS = ['bedrock-agentcore:CreatePolicy'];

/**
 * Update permissions for policy resources
 */
export const POLICY_UPDATE_PERMS = ['bedrock-agentcore:UpdatePolicy'];

/**
 * Delete permissions for policy resources
 */
export const POLICY_DELETE_PERMS = ['bedrock-agentcore:DeletePolicy'];

/**
 * Combined manage permissions for policies (create, update, delete)
 */
export const POLICY_MANAGE_PERMS = [...new Set([...POLICY_CREATE_PERMS, ...POLICY_UPDATE_PERMS, ...POLICY_DELETE_PERMS])];
