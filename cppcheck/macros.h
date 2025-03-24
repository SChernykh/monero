#define __cppcheck__

#define __GNUC__
#define RAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN
#define RAPIDJSON_64BIT=1
#define PROTOBUF_VERSION=3021012
#define PROTOBUF_MIN_PROTOC_VERSION=3021000

#define BOOST_CLASS_VERSION(...)
#define BOOST_PP_STRINGIZE(...)

#define PROTOBUF_NAMESPACE "google::protobuf"
#define PROTOBUF_NAMESPACE_ID google::protobuf

#define PROTOBUF_NAMESPACE_OPEN \
  namespace google {            \
  namespace protobuf {
#define PROTOBUF_NAMESPACE_CLOSE \
  } /* namespace protobuf */     \
  } /* namespace google */
