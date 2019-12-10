#include <algorithm>

#ifndef RSA_INC
/**
* Perform a exponent mod some number by use of successive squares
*/
template<typename T>
T mod_exponent(T num, T exponent, T mod) {
	T working_exponent = exponent; //the exponent we still have to take the working power to
	T working_power = num; //the square that we are currently working with
	T result = 1; //the output power we have so far

	while (working_exponent > 0) {
		if (working_exponent % 2 == 1) { //if the least-significant digit is zero, multiply by the working power, since this exponent of two is in the final result
			result = (result * working_power) % mod;
		}

		working_power = (working_power * working_power) % mod; //square the working power
		working_exponent >>= 1; //bitshift the working exponent by one
	}
	return result;
}

/**
* Calculate the mod inverse of a number given a modulus
*/
template<typename T>
T mod_inverse(T a, T m) {
	//perform the Euclidean algorithm
	T top_left = m;
	long long int top_right = 0;

	T bottom_left = a;
	long long int bottom_right = 1;

	while (bottom_left > 0) {
		T quotient = top_left / bottom_left;

		T old_bottom_left = bottom_left;
		bottom_left = top_left % bottom_left;
		top_left = old_bottom_left;

		long long int old_bottom_right = bottom_right;
		bottom_right = top_right - quotient * bottom_right;
		top_right = old_bottom_right;
	}

	return top_right < 0 ? top_right + m : top_right;
}

/**
* A public encryption key
*/
template<typename U, typename E>
class PublicEncryptionKey {
	public:
		const E pub_e, //the exponent
				pub_n; //the modulus

		PublicEncryptionKey(E in_e, E in_n) :
			pub_e(in_e),
			pub_n(in_n) {};

		PublicEncryptionKey() : PublicEncryptionKey(0, 0) {};

		PublicEncryptionKey(const PublicEncryptionKey& other) : PublicEncryptionKey(other.pub_e, other.pub_n) {};

		/**
		* Encrypt a value with this public key
		*/
		E encrypt(U unencrypted) const {
			return mod_exponent<E>(unencrypted, pub_e, pub_n);
		}

		PublicEncryptionKey operator=(const PublicEncryptionKey& other) {
			return PublicEncryptionKey(other.pub_e, other.pub_n);
		}

		inline operator bool() const {
			return pub_n > 0;
		}
};

/**
* A private encryption key
*/
template<typename U, typename E>
class PrivateEncryptionKey {
	public:
		PrivateEncryptionKey(E in_p, E in_q) :
			priv_p(in_p),
			priv_q(in_q),
			totient((priv_p - 1) * (priv_q - 1)),
			pub_key(PublicEncryptionKey<U, E>(smallest_coprime(totient), in_p * in_q)),
			priv_d(mod_inverse(pub_key.pub_e, totient)) {}

		/**
		* Unencrypt an encrypted bit sequence with this private key
		*/
		U decrypt(E encrypted) const {
			return (U)mod_exponent<E>(encrypted, priv_d, pub_key.pub_n);
		}

	private:
		const E priv_p, priv_q, //the two primes used to generate the key
				totient; //the totient of the product of the two primes

		/**
		* Return the smallest number coprime with a given number
		*/
		static E smallest_coprime(E num) {
			E guess = 2;
			while (std::__gcd(guess, num) > 1) {
				guess++;
			}
			return guess;
		}

	public:
		const PublicEncryptionKey<U, E> pub_key; //the public key associated with this private key

	private:
		const E priv_d; //the power to which to raise numbers to decrypt them
};
#define RSA_INC
#endif // RSA_INC
