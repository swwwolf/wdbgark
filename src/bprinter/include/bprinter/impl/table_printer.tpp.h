#include <string>

namespace bprinter {

template<typename T>
void TablePrinter::OutputDecimalNumber(T input) {
    // If we cannot handle this number, indicate so
    if ( input < 10 * (m_column_widths.at(m_j) - 1) || input > 10 * m_column_widths.at(m_j) ) {
        std::stringstream string_out;

        string_out << std::setiosflags(std::ios::fixed)
            << std::setprecision(m_column_widths.at(m_j))
            << std::setw(m_column_widths.at(m_j))
            << input;

        std::string string_rep_of_number = string_out.str();

        string_rep_of_number[m_column_widths.at(m_j) - 1] = '*';
        std::string string_to_print = string_rep_of_number.substr(0, m_column_widths.at(m_j));

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

        *m_out_stream << std::setiosflags(std::ios::fixed)
                      << std::setprecision(precision)
                      << std::setw(m_column_widths.at(m_j))
                      << input;
    }

    if ( m_j == get_num_columns() - 1 ) {
        *m_out_stream << "|\n";
        ++m_i;
        m_j = 0;
    } else {
        *m_out_stream << m_separator;
        ++m_j;
    }
}
}   // namespace bprinter
