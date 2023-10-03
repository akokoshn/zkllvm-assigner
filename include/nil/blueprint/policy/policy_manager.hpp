//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Kokoshnikov <alexeikokoshnikov@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ASSIGNER_POLICY_MANAGER_HPP
#define CRYPTO3_ASSIGNER_POLICY_MANAGER_HPP

#include <algorithm>
#include <map>

#include <nil/blueprint/policy/default_policy.hpp>
#include <nil/blueprint/policy/min_rows_policy.hpp>
#include <nil/blueprint/policy/no_packing_policy.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

            enum class policy_kind {
                DEFAULT,
                MIN_ROWS,
                NO_PACKING
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            struct PolicyManager {
                static FlexibleParameters get_parameters(
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>& assignment,
                        const std::vector <std::pair<std::uint32_t, std::uint32_t>> &witness_variants, const std::uint32_t constant_amount) {
                    if (!policy) {
                        policy.reset(new DefaultPolicy<BlueprintFieldType, ArithmetizationParams>());
                    }
                    return policy->get_parameters(assignment, witness_variants, constant_amount);
                }

                static void set_policy(policy_kind kind) {
                    switch (kind) {
                        case policy_kind::MIN_ROWS: {
                            policy.reset(new MinRowsPolicy<BlueprintFieldType, ArithmetizationParams>());
                            return;
                        }
                        case policy_kind::NO_PACKING: {
                            policy.reset(new NoPackingPolicy<BlueprintFieldType, ArithmetizationParams>());
                            return;
                        }
                        case policy_kind::DEFAULT:
                        default: {
                            policy.reset(new DefaultPolicy<BlueprintFieldType, ArithmetizationParams>());
                        }
                    }
                }

                static void set_policy(const std::string &kind_str) {
                    const auto it = policy_kind_map.find(kind_str);
                    if (it != policy_kind_map.end()) {
                        set_policy(it->second);
                    }
                }
            private:
                inline static std::shared_ptr <Policy<BlueprintFieldType, ArithmetizationParams>> policy = nullptr;

                inline static const std::map<std::string, policy_kind> policy_kind_map = {
                        {"default", policy_kind::DEFAULT},
                        {"min_rows", policy_kind::MIN_ROWS},
                        {"no_packing", policy_kind::NO_PACKING}
                };
            };
        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_POLICY_MANAGER_HPP
