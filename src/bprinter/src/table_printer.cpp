#include <stdexcept>
#include <iomanip>
#include <stdexcept>
#include <bprinter/table_printer.h>

namespace bprinter {
TablePrinter::TablePrinter(std::ostream * output, const std::string & separator){
  out_stream_ = output;
  i_ = 0;
  j_ = 0;
  separator_ = separator;
  table_width_ = 0;
}

TablePrinter::~TablePrinter(){
    out_stream_ = nullptr;
}

int TablePrinter::get_num_columns() const {
  return static_cast<int>( column_headers_.size() );
}

int TablePrinter::get_table_width() const {
  return table_width_;
}

void TablePrinter::set_separator(const std::string &separator){
  separator_ = separator;
}

/** \brief Add a column to our table
 ** 
 ** \param header_name Name to be print for the header
 ** \param column_width the width of the column (has to be >=5)
 ** */
void TablePrinter::AddColumn(const std::string & header_name, int column_width){
  if (column_width < 4){
    throw std::invalid_argument("Column size has to be >= 4");
  }

  column_headers_.push_back(header_name);
  column_widths_.push_back(column_width);
  table_width_ += column_width + static_cast<int>( separator_.size() ); // for the separator  
}

void TablePrinter::PrintHorizontalLine() {
  *out_stream_ << "+"; // the left bar

  for (int i=0; i<table_width_-1; ++i)
    *out_stream_ << "-";

  *out_stream_ << "+"; // the right bar
  *out_stream_ << "\n";
}

void TablePrinter::PrintHeader(){
  PrintHorizontalLine();
  *out_stream_ << "|";

  for (int i=0; i<get_num_columns(); ++i){
    *out_stream_ << std::setw(column_widths_.at(i)) << column_headers_.at(i).substr(0, column_widths_.at(i));
    if (i != get_num_columns()-1){
      *out_stream_ << separator_;
    }
  }

  *out_stream_ << "|\n";
  PrintHorizontalLine();
  flush_out();
}

void TablePrinter::PrintFooter(){
  PrintHorizontalLine();
  flush_out();
}

TablePrinter& TablePrinter::operator<<(float input){
  OutputDecimalNumber<float>(input);
  return *this;
}

TablePrinter& TablePrinter::operator<<(double input){
  OutputDecimalNumber<double>(input);
  return *this;
}

}
