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

#ifndef CRYPTO3_ASSIGNER_MIN_ROWS_POLICY_HPP
#define CRYPTO3_ASSIGNER_MIN_ROWS_POLICY_HPP

#include <algorithm>

#include <nil/blueprint/policy/policy.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            struct MinRowsPolicy: public Policy<BlueprintFieldType, ArithmetizationParams> {
                FlexibleParameters get_parameters(
                        const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>& assignment,
                        const std::vector<std::pair<std::uint32_t, std::uint32_t>>& witness_variants, const std::uint32_t constant_amount) const override {
                    if (witness_variants.size() == 0) {
                        return FlexibleParameters(0, 0, 0, 0);
                    }
                    auto witness_amount = witness_variants[0].first;
                    std::uint32_t start_witness_idx = 0;
                    std::uint32_t start_constant_idx = 0;
                    auto start_row = assignment.get_first_free_row(witness_amount, constant_amount, start_witness_idx, start_constant_idx);
                    auto min_rows = start_row + witness_variants[0].second;
                    for (const auto& v : witness_variants) {
                        std::uint32_t witness_idx = 0;
                        std::uint32_t constant_idx = 0;
                        const auto first_free_row = assignment.get_first_free_row(v.first, constant_amount, witness_idx, constant_idx);
                        const auto num_rows = first_free_row + v.second;
                        if (num_rows < min_rows) {
                            min_rows = num_rows;
                            witness_amount = v.first;
                            start_witness_idx = witness_idx;
                            start_constant_idx = constant_idx;
                            start_row = first_free_row;
                        }
                    }
                    return FlexibleParameters(witness_amount, start_row, start_witness_idx, start_constant_idx);
                }
            };
        }    // namespace detail
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_MIN_ROWS_POLICY_HPP
