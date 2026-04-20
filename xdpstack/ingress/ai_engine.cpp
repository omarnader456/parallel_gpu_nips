#include <iostream>
#include <fstream>
#include <mutex> 
#include <NvInfer.h>
#include <cuda_runtime_api.h>
#include <xgboost/c_api.h>

using namespace nvinfer1;

class Logger : public ILogger {
    void log(Severity severity, const char* msg) noexcept override {
        if (severity <= Severity::kWARNING) std::cout << msg << std::endl;
    }
} gLogger;

IRuntime* trt_runtime = nullptr;
ICudaEngine* trt_engine = nullptr;
IExecutionContext* trt_context = nullptr;
BoosterHandle xgb_booster;

void* d_input;
void* d_embedding;

std::mutex infer_mutex; 

extern "C" void init_ai_models(const char* trt_path, const char* xgb_path) {
    std::ifstream file(trt_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "\n[AI ENGINE ERROR] Could not open " << trt_path << std::endl;
        exit(1);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    char* buffer = new char[size];
    
    if (file.read(buffer, size)) {
        trt_runtime = createInferRuntime(gLogger);
        trt_engine = trt_runtime->deserializeCudaEngine(buffer, size);
        
        if (!trt_engine) {
            std::cerr << "\n[AI ENGINE ERROR] TensorRT failed to deserialize." << std::endl;
            exit(1);
        }
        
        trt_context = trt_engine->createExecutionContext();
    }
    delete[] buffer;

    cudaMalloc(&d_input, 1 * 10 * 6 * sizeof(float)); 
    cudaMalloc(&d_embedding, 1 * 64 * sizeof(float)); 

    XGBoosterCreate(NULL, 0, &xgb_booster);
    if (XGBoosterLoadModel(xgb_booster, xgb_path) != 0) {
        std::cerr << "\n[AI ENGINE ERROR] Failed to load XGBoost model." << std::endl;
        exit(1);
    }
    
    std::cout << "AI ENGINE Models loaded successfully!" << std::endl;
}

extern "C" bool run_hybrid_inference(float* sequence_data) {
    std::lock_guard<std::mutex> lock(infer_mutex);

    float embedding[64];
    cudaMemcpy(d_input, sequence_data, 10 * 6 * sizeof(float), cudaMemcpyHostToDevice);
    void* bindings[] = {d_input, d_embedding};
    trt_context->executeV2(bindings); 
    cudaMemcpy(embedding, d_embedding, 64 * sizeof(float), cudaMemcpyDeviceToHost);

    DMatrixHandle dmat;
    XGDMatrixCreateFromMat(embedding, 1, 64, -1, &dmat);
    
    bst_ulong out_len;
    const float* out_result;
    XGBoosterPredict(xgb_booster, dmat, 0, 0, 0, &out_len, &out_result);
    
    bool is_malicious = out_result[0] > 0.5f;
    XGDMatrixFree(dmat);
    
    return is_malicious;
}