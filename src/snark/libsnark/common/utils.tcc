/** @file
 *****************************************************************************
 Implementation of templatized utility functions
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef UTILS_TCC_
#define UTILS_TCC_

namespace libsnark {

template<typename T>
#ifdef WIN32
uint64_t size_in_bits(const std::vector<T> &v)
#else
size_t size_in_bits(const std::vector<T> &v)
#endif
{
    return v.size() * T::size_in_bits();
}

} // libsnark

#endif // UTILS_TCC_
