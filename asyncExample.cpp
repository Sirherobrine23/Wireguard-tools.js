#include <napi.h>

class Worked : public Napi::AsyncWorker {
  private:
  // All recive datas, not includes Node Inputs

  public:
  ~Worked() {}
  Worked(const Napi::Function& callback) : AsyncWorker(callback) {}

  // Another Thread
  void Execute() override {
    // Success exit so set "return;"

    // Set if example call error
    std::string errMsg = "Error example";
    SetError(errMsg);
    return;
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({
      Env().Null(),
      // another args
    });
  }

  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    const Napi::Value ee = e.Value();
    Callback().Call({
      ee,
      Env().Null()
    });
  }
};

Napi::Value WriteSessionBuffer(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();

  // Callback function is latest argument
  Worked* Write = new Worked(info[info.Length() - 1].As<Napi::Function>());
  Write->Queue();
  return env.Undefined();
}