#ifndef BASE_THREAD_SAFE_PTR_H_
#define BASE_THREAD_SAFE_PTR_H_

#include <mutex>
#include <type_traits>

namespace base{
template <typename T>
class ThreadSafe
{
	T t;
	mutable std::mutex mx;
	class Proxy{
		std::unique_lock<std::mutex> lock;
		T& t;
	public:
		explicit Proxy(std::mutex& mx, T& t) : lock(mx), t(t) {  }
		Proxy(Proxy&& src) : lock(std::move(src.lock)), t(src.t) { }
		virtual ~Proxy() {  }
		T *operator -> () { return &t; }
	};
public:
	template <typename ...Args>
	explicit ThreadSafe(Args&&... args) : t(std::forward<Args>(args)...) { }
	Proxy operator -> () { return Proxy(mx, t); }
	template <typename Func, typename R = typename std::enable_if<!std::is_void<typename std::result_of<Func(T&)>::type>::value>::type>
	auto operator () (const Func& func) {
		std::lock_guard<std::mutex> lock(mx);
		return func(t);
	}
	template <typename Func, typename R = typename std::enable_if<std::is_void<typename std::result_of<Func(T&)>::type>::value>::type>
	void operator () (const Func& func) {
		func( * operator -> () . operator -> () );
	}
};
}


#endif