//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP
#define CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP

#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/TypedPointerType.h"

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>

#include <nil/blueprint/asserts.hpp>
#include <nil/blueprint/stack.hpp>
#include <nil/blueprint/policy/policy_manager.hpp>

namespace nil {
    namespace blueprint {
        namespace detail {

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::bit_decomposition<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_field_decomposition_component(
            std::size_t BitsAmount,
            llvm::Value *operand0,
            llvm::Value *operand_sig_bit,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            using mode = nil::blueprint::components::bit_composition_mode;

            var component_input = variables[operand0];
            var sig_bit_var = variables[operand_sig_bit]; // TODO should be input of blueprint component, not as there

            bool is_msb = bool(typename BlueprintFieldType::integral_type(var_value(assignment, sig_bit_var).data));
            mode Mode = is_msb ? mode::MSB : mode::LSB;

            using component_type = nil::blueprint::components::bit_decomposition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            const auto p = PolicyManager<BlueprintFieldType, ArithmetizationParams>::get_parameters(assignment, ManifestReader<component_type, ArithmetizationParams>::get_witness(0, BitsAmount), ManifestReader<component_type, ArithmetizationParams>::constant_amount);
            component_type component_instance =  component_type(p.witness, ManifestReader<component_type, ArithmetizationParams>::get_constants(p.constant_idx), ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), BitsAmount, Mode);

            components::generate_circuit(component_instance, bp, assignment, {component_input}, p.start_row);
            return components::generate_assignments(component_instance, assignment, {component_input}, p.start_row);

            }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        typename components::bit_composition<
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>::result_type
            handle_native_field_bit_composition128_component(
            llvm::Value *operand0,
            llvm::Value *operand1,
            llvm::Value *operand_sig_bit,
            typename std::map<const llvm::Value *, std::vector<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> &vectors,
            typename std::map<const llvm::Value *, crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &variables,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment) {

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

            using component_type = nil::blueprint::components::bit_composition<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            using mode = nil::blueprint::components::bit_composition_mode;

            std::vector<var> component_input = vectors[operand0];
            component_input.insert(component_input.end(), vectors[operand1].begin(), vectors[operand1].end());
            var sig_bit_var = variables[operand_sig_bit]; // TODO should be input of blueprint component, not as there

            bool is_msb = bool(typename BlueprintFieldType::integral_type(var_value(assignment, sig_bit_var).data));
            mode Mode = is_msb ? mode::MSB : mode::LSB;
            const auto p = PolicyManager<BlueprintFieldType, ArithmetizationParams>::get_parameters(assignment, ManifestReader<component_type, ArithmetizationParams>::get_witness(0, 128, true), ManifestReader<component_type, ArithmetizationParams>::constant_amount);
            component_type component_instance =  component_type(p.witness, ManifestReader<component_type, ArithmetizationParams>::get_constants(p.constant_idx), ManifestReader<component_type, ArithmetizationParams>::get_public_inputs(), 128, true, Mode);

            components::generate_circuit(component_instance, bp, assignment, {component_input}, p.start_row);
            return components::generate_assignments(component_instance, assignment, {component_input}, p.start_row);

            }
        }    // namespace detail

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_integer_bit_decomposition_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand_sig_bit = inst->getOperand(1);

            std::size_t bitness = inst->getOperand(0)->getType()->getPrimitiveSizeInBits();

            frame.vectors[inst] = detail::handle_native_field_decomposition_component<BlueprintFieldType, ArithmetizationParams>(
                                bitness, operand0, operand_sig_bit, frame.vectors, frame.scalars, bp, assignment).output;


        }

        template<typename BlueprintFieldType, typename ArithmetizationParams>
        void handle_integer_bit_composition128_component(
            const llvm::Instruction *inst,
            stack_frame<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> &frame,
            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                &assignment) {

            using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            llvm::Value *operand0 = inst->getOperand(0);
            llvm::Value *operand1 = inst->getOperand(1);
            llvm::Value *operand_sig_bit = inst->getOperand(2);

            frame.scalars[inst] = detail::handle_native_field_bit_composition128_component<BlueprintFieldType, ArithmetizationParams>(
                                operand0, operand1, operand_sig_bit, frame.vectors, frame.scalars, bp, assignment).output;

        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ASSIGNER_INTEGER_BIT_DE_COMPOSITION_HPP
