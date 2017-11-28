#ifndef BPRINTER_TABLE_PRINTER_H_
#define BPRINTER_TABLE_PRINTER_H_

#include <engextcpp.hpp>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>

#include "..\..\..\manipulators.hpp"

namespace bprinter {

template <class T>
struct TpTraits {};

template <>
struct TpTraits<char> {
    static auto constexpr sep = "|";
    static auto constexpr p = "+";
    static auto constexpr m = "-";
    static auto constexpr a = "*";
    static auto constexpr empty = "";
};

template <>
struct TpTraits<wchar_t> {
    static auto constexpr sep = L"|";
    static auto constexpr p = L"+";
    static auto constexpr m = L"-";
    static auto constexpr a = L"*";
    static auto constexpr empty = L"";
};

class endl {};

template <class T>
class TablePrinter {
 public:
    explicit TablePrinter(std::basic_ostream<T>* output,
                          const std::basic_string<T> &separator = std::basic_string<T>(TpTraits<T>::sep))
        : m_out_stream(output),
          m_separator(separator) {}

    ~TablePrinter() { m_out_stream = nullptr; }

    size_t get_num_columns() const { return m_column_headers.size(); }
    size_t get_table_width() const { return m_table_width; }
    void set_separator(const std::basic_string<T> &separator) { m_separator = separator; }

    void AddColumn(const std::basic_string<T> &header_name, const size_t column_width) {
        if ( column_width < m_column_width_min ) {
            throw std::invalid_argument("Column size has to be >= 4");
        }

        m_column_headers.push_back(header_name);
        m_column_widths.push_back(column_width);
        m_table_width += column_width + m_separator.size();   // for the separator
    }

    void PrintHeader() {
        PrintHorizontalLine();
        *m_out_stream << TpTraits<T>::sep;

        for ( size_t i = 0; i < get_num_columns(); ++i ) {
            *m_out_stream << std::setw(m_column_widths.at(i));
            *m_out_stream << m_column_headers.at(i).substr(0, m_column_widths.at(i));

            if ( i != get_num_columns() - 1 ) {
                *m_out_stream << m_separator;
            }
        }

        *m_out_stream << TpTraits<T>::sep;
        flush_out();
        PrintHorizontalLine();
    }

    void PrintFooter() { PrintHorizontalLine(); }

    void flush_out() {
        *this << bprinter::endl();
        *m_out_stream << wa::endlout<T>;
    }

    void flush_warn() {
        *this << bprinter::endl();
        *m_out_stream << wa::endlwarn<T>;
    }

    void flush_err() {
        *this << bprinter::endl();
        *m_out_stream << wa::endlerr<T>;
    }

    TablePrinter<T>& operator<<(endl) {
        while ( m_j != 0 ) {
            *this << TpTraits<T>::empty;
        }

        return *this;
    }

    TablePrinter<T>& operator<<(float input) {
        OutputDecimalNumber<float>(input);
        return *this;
    }

    TablePrinter<T>& operator<<(double input) {
        OutputDecimalNumber<double>(input);
        return *this;
    }

    template<class I>
    TablePrinter<T>& operator<<(I input) {
        if ( m_j == 0 ) {
            *m_out_stream << TpTraits<T>::sep;
        }

        // Leave 3 extra space: One for negative sign, one for zero, one for decimal
        *m_out_stream << std::setw(m_column_widths.at(m_j)) << input;

        if ( m_j == get_num_columns() - 1 ) {
            *m_out_stream << TpTraits<T>::sep;
            ++m_i;
            m_j = 0;
        } else {
            *m_out_stream << m_separator;
            ++m_j;
        }

        return *this;
    }

 private:
    void PrintHorizontalLine() {
        *m_out_stream << TpTraits<T>::p;  // the left bar

        for ( size_t i = 0; i < m_table_width - 1; ++i ) {
            *m_out_stream << TpTraits<T>::m;
        }

        *m_out_stream << TpTraits<T>::p;  // the right bar
        flush_out();
    }

    template<class I>
    void OutputDecimalNumber(I input) {
        // If we cannot handle this number, indicate so
        if ( input < 10 * (m_column_widths.at(m_j) - 1) || input > 10 * m_column_widths.at(m_j) ) {
            std::basic_stringstream<T> string_out;

            string_out << std::setiosflags(std::ios::fixed) << std::setprecision(m_column_widths.at(m_j));
            string_out << std::setw(m_column_widths.at(m_j)) << input;

            auto string_rep_of_number = string_out.str();

            string_rep_of_number[m_column_widths.at(m_j) - 1] = TpTraits<T>::a;
            auto string_to_print = string_rep_of_number.substr(0, m_column_widths.at(m_j));

            *m_out_stream << string_to_print;
        } else {
            // determine what precision we need
            ptrdiff_t precision = m_column_widths.at(m_j) - 1;  // leave room for the decimal point

            if ( input < 0 ) {
                --precision;                                    // leave room for the minus sign
            }

            // leave room for digits before the decimal?
            if ( input < -1 || input > 1 ) {
                const auto num_digits_before_decimal = 1 + static_cast<ptrdiff_t>(log10(std::abs(input)));
                precision -= num_digits_before_decimal;
            } else {
                --precision;                                    // e.g. 0.12345 or -0.1234
            }

            if ( precision < 0 ) {
                precision = 0;                                  // don't go negative with precision
            }

            *m_out_stream << std::setiosflags(std::ios::fixed) << std::setprecision(precision);
            *m_out_stream << std::setw(m_column_widths.at(m_j)) << input;
        }

        if ( m_j == get_num_columns() - 1 ) {
            *m_out_stream << TpTraits<T>::sep << ManipTraits<T>::nl;
            ++m_i;
            m_j = 0;
        } else {
            *m_out_stream << m_separator;
            ++m_j;
        }
    }

 private:
    std::basic_ostream<T>* m_out_stream = nullptr;
    std::vector<std::basic_string<T>> m_column_headers{};
    std::vector<size_t> m_column_widths{};
    std::basic_string<T> m_separator{};

    size_t m_i = 0;   // index of current row
    size_t m_j = 0;   // index of current column
    size_t m_table_width = 0;

    size_t m_column_width_min = 4;
};

}   // namespace bprinter

#endif  // BPRINTER_TABLE_PRINTER_H_
