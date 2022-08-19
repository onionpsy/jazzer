// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlFactory;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;

import javax.xml.stream.XMLInputFactory;
import java.io.IOException;

public class XxeFuzzer {

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    XMLInputFactory xmlIn = XMLInputFactory.newFactory();
    //xmlIn.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
    // xmlIn.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
    XmlFactory factory = new XmlFactory(xmlIn);
    ObjectMapper mapper = new XmlMapper(factory);

    String foo = "<!DOCTYPE jaxxe SYSTEM \"http://localhost:3333\">";

    try {
      mapper.readTree(foo);
    } catch (IOException e) {
      //System.out.println(e);
    }
  }
}
