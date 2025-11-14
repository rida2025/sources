#include <iostream>
#include <vector>
#include <memory>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Linker/Linker.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <remill/Arch/Name.h>

int main() {
    llvm::LLVMContext context;
    auto arch = remill::Arch::Build(&context, remill::kOSLinux, remill::kArchAMD64);
    if (!arch) {
        std::cerr << "Failed to get architecture!" << std::endl;
        return 1;
    }
    auto semantics_module = remill::LoadArchSemantics(arch.get());
    std::cout << "Semantics module name: " << semantics_module->getName().str() << std::endl;
    std::cout << "Semantics module functions: " << semantics_module->getFunctionList().size() << std::endl;
    arch->InitFromSemanticsModule(semantics_module.get());
    
    remill::IntrinsicTable intrinsics(semantics_module.get());
    auto lifter = std::make_unique<remill::InstructionLifter>(arch.get(), intrinsics);
    
    struct InstructionBytes {
        std::string bytes;
        uint64_t address;
        std::string description;
    };
    std::vector<InstructionBytes> instructions = {
        {"\x55", 0x401110, "push rbp"},
        {"\x48\x89\xe5", 0x401111, "mov rbp, rsp"},
        {"\xc7\x45\xfc\x00\x00\x00\x00", 0x401114, "mov [rbp-4], 0"},
        {"\xc7\x45\xf8\x19\x00\x00\x00", 0x40111b, "mov [rbp-8], 25"},
        {"\x8b\x45\xf8", 0x401122, "mov eax, [rbp-8]"},
        {"\x5d", 0x401125, "pop rbp"},
        {"\xc3", 0x401126, "ret"}
    };
    auto Int32Ty = llvm::Type::getInt32Ty(context);
    auto func_type = llvm::FunctionType::get(Int32Ty, false);
    auto main_func = llvm::Function::Create(
        func_type, 
        llvm::Function::ExternalLinkage, 
        "main", 
        semantics_module.get()
    );
    auto entry_block = llvm::BasicBlock::Create(context, "entry", main_func);
    std::cout << "\n=== LIFTING INSTRUCTIONS ===" << std::endl;
    auto dctx = arch->CreateInitialContext();
    for (const auto& inst_data : instructions) {
        std::cout << "Lifting: " << inst_data.description << " at address 0x" << std::hex << inst_data.address << std::endl;
        std::cout << "[" << inst_data.bytes << "] == [" << inst_data.bytes.data() << "]" << std::endl;
        remill::Instruction decoded_inst;
        bool success = arch->DecodeInstruction(
            inst_data.address,
            inst_data.bytes.data(),
            decoded_inst,
            dctx
        );
        
        if (!success) {
            std::cerr << "  ❌ Failed to decode instruction: " << inst_data.description << std::endl;
            continue;
        }
        std::cout << "  ✅ Decoded: " << decoded_inst.Serialize() << std::endl;
        auto state_type = llvm::PointerType::get(llvm::Type::getInt8Ty(context), 0);
        auto state_ptr = llvm::Constant::getNullValue(state_type);
        try {
            lifter->LiftIntoBlock(
                decoded_inst,
                entry_block,
                state_ptr,
                false
            );
            std::cout << "  ✅ Successfully lifted!" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "  ❌ Failed to lift: " << e.what() << std::endl;
        }
        std::cout << std::endl;
    }
    
    // Add terminator to basic block
    llvm::IRBuilder<> builder(entry_block);
    if (!entry_block->getTerminator()) {
        builder.SetInsertPoint(entry_block);
        builder.CreateRetVoid();
        builder.CreateRet(llvm::ConstantInt::get(Int32Ty, 0));
    }

    std::cout << "Final module functions: " << std::dec << semantics_module->getFunctionList().size() << std::endl;
    
    // Save the lifted IR to a .ll file
    std::cout << "\n=== SAVING TO FILE ===" << std::endl;
    std::error_code EC;
    llvm::raw_fd_ostream file("lifted_main.ll", EC);
    if (EC) {
        std::cerr << "Error opening file: " << EC.message() << std::endl;
        return 1;
    }
    
    semantics_module->print(file, nullptr);
    file.close();
    std::cout << "✅ Saved lifted IR to 'lifted_main.ll'" << std::endl;
    
    std::cout << "\n=== HOW TO COMPILE ===" << std::endl;
    std::cout << "To compile the lifted IR:" << std::endl;
    std::cout << "1. llc lifted_main.ll -o lifted_main.s" << std::endl;
    std::cout << "2. clang lifted_main.s -o lifted_main" << std::endl;
    std::cout << "3. ./lifted_main" << std::endl;
    
    return 0;
}
